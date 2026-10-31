use super::*;
use std::fs::{DirBuilder, File};
use std::io::Read;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::DirBuilderExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::thread;

/// A directory under the temporary directory, removed when it goes out of scope. `tmp` in it is the directory that
/// stays reachable, and `outside` is a file next to it.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tkv-sandbox-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        for sub in ["", "tmp"] {
            DirBuilder::new().mode(0o700).create(dir.join(sub)).unwrap();
        }
        fs::write(dir.join("outside"), "readable").unwrap();
        Scratch(dir)
    }

    fn tmp(&self) -> PathBuf {
        self.0.join("tmp")
    }

    fn outside(&self) -> PathBuf {
        self.0.join("outside")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// The rights handled at the borders where a version adds some: 1 to 2 (REFER), 2 to 3 (TRUNCATE), 3 to 4 (TCP),
// 4 to 5 (IOCTL_DEV). A version that this code does not know handles what the last one it knows does.
#[test]
fn the_rights_handled_follow_the_abi_of_the_kernel() {
    for (abi, fs_rights, net_rights) in [
        (1, 0x1fff, 0),
        (2, 0x3fff, 0),
        (3, 0x7fff, 0),
        (4, 0x7fff, 0x3),
        (5, 0xffff, 0x3),
        (8, 0xffff, 0x3),
    ] {
        assert_eq!(handled_rights(abi), (fs_rights, net_rights), "abi {abi}");
    }
}

// A kernel without Landlock (ENOSYS) or with it switched off (EOPNOTSUPP) is "not available"; any other errno is an
// error that keeps its errno.
#[test]
fn a_kernel_without_landlock_is_told_from_another_failure() {
    for errno in [libc::ENOSYS, libc::EOPNOTSUPP] {
        assert_eq!(abi_error(errno), Error::NoLandlock);
    }
    for errno in [libc::EPERM, libc::EINVAL] {
        assert_eq!(
            abi_error(errno),
            Error::Call {
                call: "landlock version",
                errno
            }
        );
    }
}

/// The text of the result of a call that touches the outside: `ok`, or the text of the errno.
fn outcome<T>(result: io::Result<T>) -> String {
    match result {
        Ok(_) => "ok".to_owned(),
        Err(e) => e.to_string(),
    }
}

/// What a file of the directory that stays reachable is for: made, written, cut, read and removed.
fn files_in(dir: &Path) -> io::Result<()> {
    let path = dir.join("probe");
    fs::write(&path, "abc")?;
    OpenOptions::new().write(true).open(&path)?.set_len(1)?;
    if fs::read(&path)? != b"a" {
        return Err(io::Error::other("the file did not read back"));
    }
    fs::remove_file(&path)
}

/// The capability sets of the calling thread as the kernel reports them, and whether `CAP_NET_BIND_SERVICE` is
/// ambient: `ok` when the effective, permitted and inheritable sets are empty and it is not.
fn capabilities_left() -> String {
    let mut header = CapHeader {
        version: CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    // SAFETY: `header` and `data` are live structs of the sizes that version 3 reads and writes.
    let got = unsafe { libc::syscall(libc::SYS_capget, &raw mut header, data.as_mut_ptr(), NONE) };
    if got != 0 {
        return format!("capget: {}", io::Error::last_os_error());
    }
    if data != [CapData::default(); 2] {
        return format!("capabilities left: {data:?}");
    }
    const CAP_NET_BIND_SERVICE: c_ulong = 10;
    // SAFETY: PR_CAP_AMBIENT_IS_SET takes plain integers, no pointer.
    let ambient = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_IS_SET as c_ulong,
            CAP_NET_BIND_SERVICE,
            NO_ARGUMENT,
            NO_ARGUMENT,
        )
    };
    if ambient != 0 {
        return format!("ambient CAP_NET_BIND_SERVICE: {ambient}");
    }
    "ok".to_owned()
}

/// Whether `no_new_privs` is set on the calling thread.
fn no_new_privs() -> String {
    // SAFETY: PR_GET_NO_NEW_PRIVS takes plain integers, no pointer.
    let value = unsafe {
        libc::prctl(
            libc::PR_GET_NO_NEW_PRIVS,
            NO_ARGUMENT,
            NO_ARGUMENT,
            NO_ARGUMENT,
            NO_ARGUMENT,
        )
    };
    if value == 1 { "ok" } else { "not set" }.to_owned()
}

/// What the child process does: restrict itself and report, one line `name=result` for each thing it then tries. A
/// refusal of the restriction is the one line, since the probes would run unrestricted.
fn probe(tmp: &Path, outside: &Path, listening: SocketAddr) -> String {
    if let Err(e) = restrict(tmp) {
        return format!("restrict={e}");
    }
    [
        "restrict=ok".to_owned(),
        format!("read outside={}", outcome(File::open(outside))),
        format!("files in TMPDIR={}", outcome(files_in(tmp))),
        format!(
            "mkdir in TMPDIR={}",
            outcome(DirBuilder::new().create(tmp.join("d")))
        ),
        format!("exec={}", outcome(Command::new("/bin/true").status())),
        format!(
            "bind={}",
            outcome(TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))))
        ),
        format!("connect={}", outcome(TcpStream::connect(listening))),
        format!("capabilities={}", capabilities_left()),
        format!("no_new_privs={}", no_new_privs()),
    ]
    .join("\n")
}

/// Runs `child` in a process of its own that has one thread: a copy of this thread made by `fork`, which is the only
/// thread that a forked process has (the test program has several). The child writes what `child` returns to a pipe
/// and leaves with `_exit`, so it never returns into the test program. Returns what it wrote and its wait status.
fn in_a_process_of_one_thread(child: impl FnOnce() -> String) -> (String, c_int) {
    let mut ends = [0 as c_int; 2];
    // SAFETY: `ends` has room for the two descriptors that pipe2 writes.
    assert_eq!(
        unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    // SAFETY: the child only runs `child` and leaves with `_exit`. It uses the allocator and the file system, which a
    // forked child of a program with threads may use on this C library, and none of the locks of the test program.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork: {}", io::Error::last_os_error());
    if pid == 0 {
        // A child that hangs is ended by the kernel, and the parent sees the signal.
        // SAFETY: alarm takes a plain integer.
        unsafe { libc::alarm(60) };
        let code = catch_unwind(AssertUnwindSafe(|| {
            let report = child();
            let mut rest = report.as_bytes();
            while !rest.is_empty() {
                // SAFETY: `ends[1]` is the open write end and `rest` is a live slice of the length passed.
                let n = unsafe { libc::write(ends[1], rest.as_ptr().cast(), rest.len()) };
                let Ok(n) = usize::try_from(n) else { return 3 };
                rest = &rest[n..];
            }
            0
        }))
        .unwrap_or(2);
        // SAFETY: the child leaves at once, without the exit handlers or the destructors of the test program.
        unsafe { libc::_exit(code) }
    }
    // SAFETY: `ends[1]` is open and only the child writes to it from here on.
    unsafe { libc::close(ends[1]) };
    // SAFETY: `ends[0]` is the read end, a descriptor that nothing else owns.
    let mut reader = unsafe { File::from_raw_fd(ends[0]) };
    let mut report = String::new();
    reader.read_to_string(&mut report).unwrap();
    let mut status = 0;
    // SAFETY: `pid` is a child of this process and `status` is a live integer.
    assert_eq!(unsafe { libc::waitpid(pid, &raw mut status, 0) }, pid);
    (report, status)
}

// The restriction cannot be undone, so it is made in a process of its own, which has one thread. The one thing that
// the report must hold is its last line: a child that ended before it had tried everything is a failure.
#[test]
fn after_the_restriction_only_tmpdir_is_reachable_and_nothing_is_left_to_do_harm() {
    let abi = landlock_abi().unwrap();
    let scratch = Scratch::new();
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    let listening = listener.local_addr().unwrap();
    let (tmp, outside) = (scratch.tmp(), scratch.outside());

    let (report, status) = in_a_process_of_one_thread(|| probe(&tmp, &outside, listening));

    let denied = io::Error::from_raw_os_error(libc::EACCES).to_string();
    let tcp = if abi >= 4 { denied.as_str() } else { "ok" }; // Landlock restricts TCP from ABI 4
    let want = [
        "restrict=ok".to_owned(),
        format!("read outside={denied}"),
        "files in TMPDIR=ok".to_owned(),
        format!("mkdir in TMPDIR={denied}"),
        format!("exec={denied}"),
        format!("bind={tcp}"),
        format!("connect={tcp}"),
        "capabilities=ok".to_owned(),
        "no_new_privs=ok".to_owned(),
    ];
    assert_eq!(
        report.lines().collect::<Vec<_>>(),
        want,
        "abi {abi}, status {status}"
    );
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "status {status}"
    );
}

// In the test program, which has several threads, the restriction is refused and nothing is restricted. A thread that
// waits makes sure there is a second one, whatever the harness runs this test on.
#[test]
fn a_process_with_more_than_one_thread_is_refused_and_nothing_is_restricted() {
    let scratch = Scratch::new();
    let (release, wait) = mpsc::channel::<()>();
    let waiting = thread::spawn(move || {
        let _ = wait.recv();
    });
    let result = restrict(&scratch.tmp());
    release.send(()).unwrap();
    waiting.join().unwrap();
    let err = result.unwrap_err();
    assert_eq!(err, Error::Threads);
    assert!(!err.to_string().contains(scratch.0.to_str().unwrap()));
    // Nothing was restricted: a file outside the directory could be opened, and a file in it created.
    assert_eq!(fs::read(scratch.outside()).unwrap(), b"readable");
    fs::write(scratch.0.join("made"), "x").unwrap();
}

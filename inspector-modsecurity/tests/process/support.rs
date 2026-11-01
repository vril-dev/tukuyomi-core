//! The start of the real process, the generation it starts with, and a reader and a writer of frames.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, DirBuilder};
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

const BIN: &str = env!("CARGO_BIN_EXE_tukuyomi-inspector-modsecurity");

pub const RUN: u64 = 0x0102_0304_0506_0708;
pub const INC: u32 = 7;
pub const NONCE: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

pub const KIND_HELLO: u8 = 0x01;
pub const KIND_DRAIN: u8 = 0x02;
pub const KIND_BYE: u8 = 0x03;
pub const KIND_TX_BEGIN: u8 = 0x10;

const HEADER_LEN: usize = 36;
const RULES_PATH: &str = "rules/rules.conf";
const RULE: &str = "SecRule ARGS \"@contains attack\" \"id:1001,phase:2,deny,status:403,log\"\n";
const WAIT: Duration = Duration::from_secs(20);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A directory under the temporary directory, removed when it goes out of scope. `generation` in it is the
/// generation of rules and `tmp` is the `TMPDIR` of the process.
pub struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tkv-process-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        for sub in ["", "generation", "tmp"] {
            DirBuilder::new().mode(0o700).create(dir.join(sub)).unwrap();
        }
        Scratch(dir)
    }

    pub fn root(&self) -> &Path {
        &self.0
    }

    pub fn generation(&self) -> PathBuf {
        self.0.join("generation")
    }

    pub fn tmp(&self) -> PathBuf {
        self.0.join("tmp")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Writes the generation of the one rule file `rules` and returns the bytes of its manifest: a manifest of version 4
/// in its one canonical form.
fn write_generation(dir: &Path, rules: &str) -> Vec<u8> {
    DirBuilder::new()
        .mode(0o700)
        .create(dir.join("rules"))
        .unwrap();
    fs::write(dir.join(RULES_PATH), rules).unwrap();
    let manifest = format!(
        r#"{{"version":4,"engine":"modsecurity","mode":"block","files":[{{"path":"{RULES_PATH}","size":{},"sha256":"{}"}}],"load":["{RULES_PATH}"],"routes":[]}}"#,
        rules.len(),
        hex(&Sha256::digest(rules.as_bytes()))
    ) + "\n";
    fs::write(dir.join("manifest.json"), &manifest).unwrap();
    manifest.into_bytes()
}

/// What descriptor 0 of the process is.
#[derive(Default)]
pub enum Input {
    /// A socket pair made by the test, which started the process.
    #[default]
    Pair,
    /// The read end of a pipe.
    Pipe,
    /// A datagram socket.
    Datagram,
    /// A socket pair made by the test, but the process is started by a shell that stays its parent.
    PairOfAnotherParent,
}

/// How a test changes the start from the one of the kernel.
#[derive(Default)]
pub struct Options {
    env: Vec<(&'static str, Option<String>)>,
    args: Option<Vec<OsString>>,
    input: Input,
    rules: Option<&'static str>,
    prepare: Option<fn(&Scratch)>,
}

impl Options {
    /// Sets a variable of the environment.
    pub fn env(mut self, name: &'static str, value: &str) -> Options {
        self.env.push((name, Some(value.to_owned())));
        self
    }

    /// Leaves a variable out of the environment.
    pub fn without(mut self, name: &'static str) -> Options {
        self.env.push((name, None));
        self
    }

    pub fn args(mut self, args: &[&str]) -> Options {
        self.args = Some(args.iter().map(OsString::from).collect());
        self
    }

    pub fn input(mut self, input: Input) -> Options {
        self.input = input;
        self
    }

    /// The text of the one rule file of the generation.
    pub fn rules(mut self, rules: &'static str) -> Options {
        self.rules = Some(rules);
        self
    }

    /// Changes the directories of the test after the generation is written and before the process starts.
    pub fn prepare(mut self, prepare: fn(&Scratch)) -> Options {
        self.prepare = Some(prepare);
        self
    }
}

/// A frame of the protocol, as the process sends it.
#[derive(Debug)]
pub struct Frame {
    pub bytes: Vec<u8>,
}

impl Frame {
    pub fn kind(&self) -> u8 {
        self.bytes[4]
    }

    pub fn flags(&self) -> u8 {
        self.bytes[5]
    }

    pub fn len(&self) -> u32 {
        u32::from_be_bytes(self.bytes[8..12].try_into().unwrap())
    }

    pub fn run(&self) -> u64 {
        u64::from_be_bytes(self.bytes[12..20].try_into().unwrap())
    }

    pub fn inc(&self) -> u32 {
        u32::from_be_bytes(self.bytes[20..24].try_into().unwrap())
    }

    pub fn tx(&self) -> u64 {
        u64::from_be_bytes(self.bytes[24..32].try_into().unwrap())
    }

    pub fn msg(&self) -> u32 {
        u32::from_be_bytes(self.bytes[32..36].try_into().unwrap())
    }

    pub fn payload(&self) -> &[u8] {
        &self.bytes[HEADER_LEN..]
    }
}

/// A frame the kernel sends, with the run and the incarnation of the process.
pub fn frame(kind: u8, tx: u64, msg: u32, payload: &[u8]) -> Vec<u8> {
    let mut b = b"TKV0".to_vec();
    b.extend_from_slice(&[kind, 0, 0, 0]);
    b.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    b.extend_from_slice(&RUN.to_be_bytes());
    b.extend_from_slice(&INC.to_be_bytes());
    b.extend_from_slice(&tx.to_be_bytes());
    b.extend_from_slice(&msg.to_be_bytes());
    b.extend_from_slice(payload);
    b
}

/// The payload of a TX_BEGIN for `GET /` with the header `Host` and no body.
pub fn tx_begin_payload() -> Vec<u8> {
    fn string(p: &mut Vec<u8>, s: &[u8]) {
        p.extend_from_slice(&u16::try_from(s.len()).unwrap().to_be_bytes());
        p.extend_from_slice(s);
    }
    let mut p = Vec::new();
    string(&mut p, b"127.0.0.1");
    p.extend_from_slice(&40000u16.to_be_bytes());
    string(&mut p, b"127.0.0.1");
    p.extend_from_slice(&8080u16.to_be_bytes());
    string(&mut p, b"GET");
    string(&mut p, b"/");
    string(&mut p, b"HTTP/1.1");
    p.extend_from_slice(&0u64.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes());
    string(&mut p, b"Host");
    string(&mut p, b"example.test");
    p
}

/// Reads one frame within a time limit; `None` when the other side has closed the connection.
pub fn read_frame(conn: &mut UnixStream) -> Option<Frame> {
    conn.set_read_timeout(Some(WAIT)).unwrap();
    let mut header = [0u8; HEADER_LEN];
    let first = loop {
        match conn.read(&mut header[..1]) {
            Ok(n) => break n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => panic!("read: {e}"),
        }
    };
    if first == 0 {
        return None;
    }
    conn.read_exact(&mut header[1..])
        .expect("the rest of the header");
    let len = u32::from_be_bytes(header[8..12].try_into().unwrap());
    let mut bytes = header.to_vec();
    bytes.resize(HEADER_LEN + usize::try_from(len).unwrap(), 0);
    conn.read_exact(&mut bytes[HEADER_LEN..])
        .expect("the payload");
    Some(Frame { bytes })
}

/// A reader of the fields of a payload.
pub struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
    pub fn new(payload: &'a [u8]) -> Fields<'a> {
        Fields(payload)
    }

    fn take(&mut self, n: usize) -> &'a [u8] {
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        head
    }

    pub fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.take(2).try_into().unwrap())
    }

    pub fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.take(4).try_into().unwrap())
    }

    pub fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.take(8).try_into().unwrap())
    }

    pub fn array<const N: usize>(&mut self) -> [u8; N] {
        self.take(N).try_into().unwrap()
    }

    /// A string with a length of two bytes before it.
    pub fn string(&mut self) -> String {
        let len = usize::from(self.u16());
        String::from_utf8(self.take(len).to_vec()).unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A process that was started, and what the test keeps of it.
pub struct Process {
    child: Child,
    /// The test's end of the connection; `None` when the process was not given a socket pair.
    pub conn: Option<UnixStream>,
    pub scratch: Scratch,
    /// The bytes of the manifest of the generation that was written.
    pub manifest: Vec<u8>,
    stderr: Option<ChildStderr>,
    stderr_read: String,
    status: Option<ExitStatus>,
}

/// Starts the inspector as the kernel does, with the changes of `options`.
pub fn start(options: Options) -> Process {
    let scratch = Scratch::new();
    let manifest = write_generation(&scratch.generation(), options.rules.unwrap_or(RULE));
    if let Some(prepare) = options.prepare {
        prepare(&scratch);
    }
    let mut env: BTreeMap<&str, Option<String>> = BTreeMap::from([
        ("TKV0_RUN_ID", Some(hex(&RUN.to_be_bytes()))),
        ("TKV0_INCARNATION", Some(hex(&INC.to_be_bytes()))),
        ("TKV0_NONCE", Some(hex(&NONCE))),
        ("TMPDIR", scratch.tmp().to_str().map(str::to_owned)),
        ("GOMAXPROCS", Some("2".to_owned())),
        ("GOMEMLIMIT", Some("268435456".to_owned())),
    ]);
    env.extend(options.env);
    let args = options
        .args
        .unwrap_or_else(|| vec![scratch.generation().into_os_string()]);

    let (conn, child_end) = match options.input {
        Input::Pair | Input::PairOfAnotherParent => {
            let (mine, theirs) = UnixStream::pair().unwrap();
            (Some(mine), Stdio::from(OwnedFd::from(theirs)))
        }
        Input::Pipe => {
            let (reader, _writer) = io::pipe().unwrap();
            (None, Stdio::from(reader))
        }
        Input::Datagram => {
            let (_mine, theirs) = UnixDatagram::pair().unwrap();
            (None, Stdio::from(OwnedFd::from(theirs)))
        }
    };
    let mut command = if matches!(options.input, Input::PairOfAnotherParent) {
        // The shell runs the inspector as its child and waits for it: the parent of the inspector is not the
        // process that made the pair.
        let mut sh = Command::new("/bin/sh");
        sh.arg("-c").arg(r#""$0" "$@"; exit $?"#).arg(BIN);
        sh
    } else {
        Command::new(BIN)
    };
    command
        .args(&args)
        .env_clear()
        .envs(env.iter().filter_map(|(k, v)| v.as_ref().map(|v| (k, v))))
        .stdin(child_end)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let spawned = command.spawn();
    // The command holds its own copy of the child's end of the pair until it is dropped: with that closed, the
    // death of the process is the end of the file for the test.
    drop(command);
    let mut child = spawned.expect("start the inspector");
    let stderr = child.stderr.take();
    Process {
        child,
        conn,
        scratch,
        manifest,
        stderr,
        stderr_read: String::new(),
        status: None,
    }
}

impl Process {
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn conn(&mut self) -> &mut UnixStream {
        self.conn.as_mut().expect("the process has a connection")
    }

    pub fn send(&mut self, bytes: &[u8]) {
        self.conn().write_all(bytes).expect("write to the process");
    }

    pub fn recv(&mut self) -> Option<Frame> {
        read_frame(self.conn())
    }

    /// The HELLO, which is the first frame.
    pub fn hello(&mut self) -> Frame {
        let hello = self.recv().expect("the process sent a HELLO");
        assert_eq!(hello.kind(), KIND_HELLO);
        hello
    }

    /// Sends the signal `name` (`TERM`, `USR1`, ...) to the process.
    pub fn signal(&self, name: &str) {
        let status = Command::new("kill")
            .arg("-s")
            .arg(name)
            .arg(self.pid().to_string())
            .status()
            .expect("run the kill command");
        assert!(status.success(), "kill -s {name} failed: {status}");
    }

    /// Waits for the end of the process, for a limited time.
    pub fn wait(&mut self) -> ExitStatus {
        if let Some(status) = self.status {
            return status;
        }
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                self.status = Some(status);
                return status;
            }
            assert!(start.elapsed() < WAIT, "the process did not end");
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// The exit code; the test fails when a signal ended the process.
    pub fn code(&mut self) -> i32 {
        let status = self.wait();
        match status.code() {
            Some(code) => code,
            None => panic!(
                "ended by signal {:?}, stderr {:?}",
                status.signal(),
                self.stderr_text()
            ),
        }
    }

    /// Everything the process wrote to its standard error; the process has ended.
    pub fn stderr_text(&mut self) -> String {
        self.wait();
        if let Some(mut stderr) = self.stderr.take() {
            let mut text = Vec::new();
            stderr.read_to_end(&mut text).unwrap();
            self.stderr_read = String::from_utf8(text).unwrap();
        }
        self.stderr_read.clone()
    }

    /// The bytes of `start-failure` in `TMPDIR` and its mode, if the file is there.
    pub fn start_failure(&self) -> Option<(Vec<u8>, u32)> {
        let path = self.scratch.tmp().join("start-failure");
        let bytes = fs::read(&path).ok()?;
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        Some((bytes, mode))
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

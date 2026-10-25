package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

// The system calls and constants below carry the names of the Linux uapi
// headers (linux/landlock.h, linux/prctl.h, linux/capability.h) in their
// comments. The syscall package has no Landlock call and, on amd64, neither
// the prctl constants nor O_PATH, so they are written out here.
const (
	sysLandlockCreateRuleset = 444 // __NR_landlock_create_ruleset (the same number on x86_64 and aarch64)
	sysLandlockAddRule       = 445 // __NR_landlock_add_rule
	sysLandlockRestrictSelf  = 446 // __NR_landlock_restrict_self

	landlockCreateRulesetVersion = 1 // LANDLOCK_CREATE_RULESET_VERSION
	landlockRulePathBeneath      = 1 // LANDLOCK_RULE_PATH_BENEATH

	prSetNoNewPrivs      = 38 // PR_SET_NO_NEW_PRIVS
	prCapAmbient         = 47 // PR_CAP_AMBIENT
	prCapAmbientClearAll = 4  // PR_CAP_AMBIENT_CLEAR_ALL

	linuxCapabilityVersion3 = 0x20080522 // _LINUX_CAPABILITY_VERSION_3

	openPath = 0x200000 // O_PATH
)

// The rights of a Landlock rule set. A right that the rule set handles is
// refused unless a rule allows it, and the kernel refuses a rule set that names
// a right it does not know (EINVAL), so the rights handled are chosen by the
// ABI version that the kernel reports (handledRights).
const (
	// ABI 1: bits 0 to 12, from EXECUTE through MAKE_SYM.
	accessFSBase = 1<<13 - 1

	accessFSWriteFile  = 1 << 1  // LANDLOCK_ACCESS_FS_WRITE_FILE
	accessFSReadFile   = 1 << 2  // LANDLOCK_ACCESS_FS_READ_FILE
	accessFSRemoveFile = 1 << 5  // LANDLOCK_ACCESS_FS_REMOVE_FILE
	accessFSMakeReg    = 1 << 8  // LANDLOCK_ACCESS_FS_MAKE_REG
	accessFSRefer      = 1 << 13 // LANDLOCK_ACCESS_FS_REFER (ABI 2)
	accessFSTruncate   = 1 << 14 // LANDLOCK_ACCESS_FS_TRUNCATE (ABI 3)
	accessFSIoctlDev   = 1 << 15 // LANDLOCK_ACCESS_FS_IOCTL_DEV (ABI 5)

	accessNetBindTCP    = 1 << 0 // LANDLOCK_ACCESS_NET_BIND_TCP (ABI 4)
	accessNetConnectTCP = 1 << 1 // LANDLOCK_ACCESS_NET_CONNECT_TCP (ABI 4)

	// What the inspector may do in TMPDIR: the files that Coraza makes there
	// (create, write, read, truncate, remove) and start-failure. It may not make
	// a directory, list one, link, rename out of it or execute anything.
	tmpDirAccess = accessFSReadFile | accessFSWriteFile | accessFSMakeReg | accessFSRemoveFile | accessFSTruncate
)

// errNoLandlock is the answer of a kernel without Landlock.
var errNoLandlock = errors.New("landlock is not available")

// sandbox takes away what the inspector does not need any more, for the whole
// process and for good: it can then reach no file outside TMPDIR, make no TCP
// connection, bind no TCP port, execute no program and has no capability left
// (an ambient CAP_NET_BIND_SERVICE of the service is inherited through exec).
// The rules are in memory by now; TMPDIR holds the temporary files of Coraza
// and start-failure, so it is the one place that stays reachable.
//
// Landlock does not restrict UDP, unix sockets or MPTCP sockets (a socket made
// with IPPROTO_MPTCP is not a TCP socket to it), so those stay open.
//
// It must run before the rules are parsed or any request is read. An error
// means the process is not (fully) restricted and must not go on. A kernel
// without Landlock gives errNoLandlock, and there is no way to run unrestricted.
//
// Landlock, no_new_privs and the capability sets belong to one thread, and the
// Go runtime has many, so each of these calls goes through AllThreadsSyscall,
// which runs it on every thread and stops the program if the threads differ.
// A binary built with cgo cannot do that (the call returns ENOTSUP), so the
// inspector is built with CGO_ENABLED=0.
func sandbox(tmpDir string) error {
	// The time zone is read from a file on first use, and the process that
	// starts the inspector passes no TZ. Read after the restriction it would
	// silently be UTC, and the TIME variables of the rules would change.
	_ = time.Local.String()

	abi, err := landlockABI()
	if err != nil {
		return err
	}
	fsRights, netRights := handledRights(abi)
	ruleset, err := createRuleset(fsRights, netRights)
	if err != nil {
		return err
	}
	defer syscall.Close(ruleset)
	if err := allowTmpDir(ruleset, tmpDir, fsRights&tmpDirAccess); err != nil {
		return err
	}
	if err := dropCapabilities(); err != nil {
		return err
	}
	// Needed by landlock_restrict_self for a process without CAP_SYS_ADMIN, and
	// it stops a later exec from gaining capabilities.
	if _, _, e := syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); e != 0 {
		return fmt.Errorf("no_new_privs: %w", e)
	}
	if _, _, e := syscall.AllThreadsSyscall(sysLandlockRestrictSelf, uintptr(ruleset), 0, 0); e != 0 {
		return fmt.Errorf("landlock restrict: %w", e)
	}
	return nil
}

// landlockABI returns the highest Landlock ABI version of the kernel.
func landlockABI() (int, error) {
	v, _, e := syscall.Syscall(sysLandlockCreateRuleset, 0, 0, landlockCreateRulesetVersion)
	if e != 0 {
		return 0, abiError(e)
	}
	if v < 1 || v > 1<<16 { // the kernel gives a small positive number
		return 0, fmt.Errorf("landlock version: unexpected value %d", v)
	}
	return int(v), nil
}

// abiError names the failure of the version query. ENOSYS is a kernel built
// without Landlock and EOPNOTSUPP one that has it switched off at boot; any
// other errno (EPERM from a filter on system calls, for one) is reported as it is.
func abiError(e syscall.Errno) error {
	if e == syscall.ENOSYS || e == syscall.EOPNOTSUPP {
		return errNoLandlock
	}
	return fmt.Errorf("landlock version: %w", e)
}

// handledRights returns the file and the TCP rights that a rule set handles on
// a kernel with the given ABI version: all that the version knows, so that
// whatever a rule does not allow is refused. A version newer than the ones
// listed here adds rights that this code does not know and so does not handle.
func handledRights(abi int) (fsRights, netRights uint64) {
	fsRights = accessFSBase
	if abi >= 2 {
		fsRights |= accessFSRefer
	}
	if abi >= 3 {
		fsRights |= accessFSTruncate
	}
	if abi >= 5 {
		fsRights |= accessFSIoctlDev
	}
	if abi >= 4 {
		netRights = accessNetBindTCP | accessNetConnectTCP
	}
	return fsRights, netRights
}

// createRuleset makes a rule set that handles the given rights and returns its
// descriptor (close-on-exec). It has no TCP rule, so a handled TCP right is
// refused for every port.
func createRuleset(fsRights, netRights uint64) (int, error) {
	// struct landlock_ruleset_attr: handled_access_fs, handled_access_net and
	// scoped, 24 bytes. A kernel that knows fewer fields accepts the longer
	// struct while the extra bytes are zero; scoped stays 0 (nothing scoped).
	var attr [24]byte
	binary.NativeEndian.PutUint64(attr[0:], fsRights)
	binary.NativeEndian.PutUint64(attr[8:], netRights)
	fd, _, e := syscall.Syscall(sysLandlockCreateRuleset, uintptr(unsafe.Pointer(&attr[0])), uintptr(len(attr)), 0)
	if e != 0 {
		return -1, fmt.Errorf("landlock ruleset: %w", e)
	}
	return int(fd), nil
}

// allowTmpDir adds the one rule of the rule set: the access of allowed to
// everything beneath dir. dir is opened as a directory and not through a
// link; the error is an errno, so it holds no path.
func allowTmpDir(ruleset int, dir string, allowed uint64) error {
	fd, err := syscall.Open(dir, openPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open TMPDIR: %w", err)
	}
	defer syscall.Close(fd)
	// struct landlock_path_beneath_attr, packed to 12 bytes: u64 allowed_access,
	// s32 parent_fd.
	var attr [12]byte
	binary.NativeEndian.PutUint64(attr[0:], allowed)
	binary.NativeEndian.PutUint32(attr[8:], uint32(fd))
	if _, _, e := syscall.Syscall6(sysLandlockAddRule, uintptr(ruleset), landlockRulePathBeneath, uintptr(unsafe.Pointer(&attr[0])), 0, 0, 0); e != 0 {
		return fmt.Errorf("landlock rule: %w", e)
	}
	return nil
}

// dropCapabilities empties the ambient set and then the effective, permitted
// and inheritable sets, on every thread. The bounding set stays: changing it
// needs CAP_SETPCAP, and with no_new_privs and an empty permitted set an exec
// cannot bring anything back.
func dropCapabilities() error {
	if _, _, e := syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, prCapAmbient, prCapAmbientClearAll, 0, 0, 0, 0); e != 0 {
		// The first call through AllThreadsSyscall: it gives ENOTSUP only in a
		// binary built with cgo, which cannot be restricted on every thread.
		if e == syscall.ENOTSUP {
			return errors.New("the inspector is built with cgo and cannot restrict every thread")
		}
		return fmt.Errorf("clear ambient capabilities: %w", e)
	}
	// struct __user_cap_header_struct: u32 version, int pid (0 is the calling
	// thread); then two __user_cap_data_struct (effective, permitted,
	// inheritable; 3 x u32 each), all zero.
	var header [8]byte
	binary.NativeEndian.PutUint32(header[0:], linuxCapabilityVersion3)
	var data [24]byte
	if _, _, e := syscall.AllThreadsSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&header[0])), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		return fmt.Errorf("drop capabilities: %w", e)
	}
	return nil
}

//go:build darwin && cgo

package main

/*
#cgo LDFLAGS: -lbsm -lproc
#include <sys/socket.h>
#include <sys/un.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <sys/proc_info.h>

static int read_peer_audit_token(int fd, uid_t *uid, pid_t *pid, int *pid_version) {
	audit_token_t token;
	socklen_t token_len = sizeof(token);
	if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &token_len) != 0 ||
	    token_len != sizeof(token)) {
		return -1;
	}
	*uid = audit_token_to_euid(token);
	*pid = audit_token_to_pid(token);
	*pid_version = audit_token_to_pidversion(token);
	return 0;
}

static int read_process_start(pid_t pid, pid_t *observed_pid, pid_t *parent_pid,
                              uid_t *observed_uid, uint64_t *start_seconds,
                              uint64_t *start_micros) {
	struct proc_bsdinfo info;
	if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != sizeof(info)) {
		return -1;
	}
	*observed_pid = info.pbi_pid;
	*parent_pid = info.pbi_ppid;
	*observed_uid = info.pbi_uid;
	*start_seconds = info.pbi_start_tvsec;
	*start_micros = info.pbi_start_tvusec;
	return 0;
}
*/
import "C"

import (
	"errors"
	"net"
)

// peerProcessIdentity is kernel-observed identity for a connected Unix peer.
// PIDVersion distinguishes a reused PID; callers must still bind it to a
// Machine-observed, signed child identity before authorizing any relay.
type peerProcessIdentity struct {
	UID        uint32
	PID        int
	PIDVersion int
}

// peerProcessSnapshot is a live kernel view of the socket peer and its direct
// parent. The socket audit token identifies its original peer, while the
// process table describes a PID that may be reused. Authorization must match
// the fresh start times to Machine's signed observation and refuse exit/reuse.
type peerProcessSnapshot struct {
	Peer               peerProcessIdentity
	StartSeconds       uint64
	StartMicros        uint64
	ParentPID          int
	ParentUID          uint32
	ParentStartSeconds uint64
	ParentStartMicros  uint64
}

func peerIdentity(conn *net.UnixConn) (peerProcessIdentity, error) {
	if conn == nil {
		return peerProcessIdentity{}, errors.New("kernel peer identity unavailable")
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return peerProcessIdentity{}, err
	}
	var uid C.uid_t
	var pid C.pid_t
	var pidVersion C.int
	result := C.int(-1)
	err = raw.Control(func(fd uintptr) {
		result = C.read_peer_audit_token(C.int(fd), &uid, &pid, &pidVersion)
	})
	if err != nil || result != 0 || pid <= 0 || pidVersion <= 0 {
		return peerProcessIdentity{}, errors.New("kernel peer identity unavailable")
	}
	return peerProcessIdentity{UID: uint32(uid), PID: int(pid), PIDVersion: int(pidVersion)}, nil
}

func observePeerProcess(conn *net.UnixConn) (peerProcessSnapshot, error) {
	peer, err := peerIdentity(conn)
	if err != nil {
		return peerProcessSnapshot{}, err
	}
	var observedPID, parentPID C.pid_t
	var observedUID C.uid_t
	var startSeconds, startMicros C.uint64_t
	if C.read_process_start(C.pid_t(peer.PID), &observedPID, &parentPID,
		&observedUID, &startSeconds, &startMicros) != 0 ||
		int(observedPID) != peer.PID || uint32(observedUID) != peer.UID ||
		parentPID <= 1 || startSeconds == 0 || startMicros >= 1000000 {
		return peerProcessSnapshot{}, errors.New("kernel peer process unavailable")
	}
	var observedParentPID, grandparentPID C.pid_t
	var observedParentUID C.uid_t
	var parentStartSeconds, parentStartMicros C.uint64_t
	if C.read_process_start(parentPID, &observedParentPID, &grandparentPID,
		&observedParentUID, &parentStartSeconds, &parentStartMicros) != 0 ||
		observedParentPID != parentPID || uint32(observedParentUID) != peer.UID ||
		parentStartSeconds == 0 || parentStartMicros >= 1000000 {
		return peerProcessSnapshot{}, errors.New("kernel peer parent unavailable")
	}
	if current, err := peerIdentity(conn); err != nil || current != peer {
		return peerProcessSnapshot{}, errors.New("kernel peer changed")
	}
	return peerProcessSnapshot{
		Peer: peer, StartSeconds: uint64(startSeconds), StartMicros: uint64(startMicros),
		ParentPID: int(parentPID), ParentUID: uint32(observedParentUID),
		ParentStartSeconds: uint64(parentStartSeconds),
		ParentStartMicros:  uint64(parentStartMicros),
	}, nil
}

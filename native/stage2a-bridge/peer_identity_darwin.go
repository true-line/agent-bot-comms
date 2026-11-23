//go:build darwin && cgo

package main

/*
#cgo LDFLAGS: -lbsm
#include <sys/socket.h>
#include <sys/un.h>
#include <bsm/libbsm.h>

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

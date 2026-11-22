//go:build darwin && cgo

package main

// #include <unistd.h>
import "C"
import (
	"errors"
	"net"
)

func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid C.uid_t
	var gid C.gid_t
	var result C.int
	err = raw.Control(func(fd uintptr) {
		result = C.getpeereid(C.int(fd), &uid, &gid)
	})
	if err != nil || result != 0 {
		return 0, errors.New("kernel peer identity unavailable")
	}
	return uint32(uid), nil
}

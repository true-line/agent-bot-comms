//go:build !darwin || !cgo

package main

import (
	"errors"
	"net"
)

type peerProcessIdentity struct {
	UID        uint32
	PID        int
	PIDVersion int
}

type peerProcessSnapshot struct {
	Peer               peerProcessIdentity
	StartSeconds       uint64
	StartMicros        uint64
	ParentPID          int
	ParentUID          uint32
	ParentStartSeconds uint64
	ParentStartMicros  uint64
}

func peerIdentity(*net.UnixConn) (peerProcessIdentity, error) {
	return peerProcessIdentity{}, errors.New("Darwin native peer identity unavailable")
}

func observePeerProcess(*net.UnixConn) (peerProcessSnapshot, error) {
	return peerProcessSnapshot{}, errors.New("Darwin native peer process unavailable")
}

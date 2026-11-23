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

func peerIdentity(*net.UnixConn) (peerProcessIdentity, error) {
	return peerProcessIdentity{}, errors.New("Darwin native peer identity unavailable")
}

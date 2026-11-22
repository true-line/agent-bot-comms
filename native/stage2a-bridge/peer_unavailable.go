//go:build !darwin || !cgo

package main

import (
	"errors"
	"net"
)

func peerUID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("Darwin native peer identity unavailable")
}

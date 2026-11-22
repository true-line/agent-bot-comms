//go:build darwin && cgo

package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeDarwinPeerUID(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "b-peer-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "peer.sock")
	addr := &net.UnixAddr{Name: path, Net: "unix"}
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for _, conn := range []*net.UnixConn{client, server} {
		uid, err := peerUID(conn)
		if err != nil || uid != uint32(os.Geteuid()) {
			t.Fatalf("kernel peer uid = %d, err = %v", uid, err)
		}
		if peerMatches(conn, uid+1, peerUID) {
			t.Fatal("incorrect UID accepted")
		}
	}
}

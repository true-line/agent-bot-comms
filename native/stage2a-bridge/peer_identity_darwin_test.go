//go:build darwin && cgo

package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPeerAuditTokenHelper(t *testing.T) {
	path := os.Getenv("STAGE2A_PEER_TEST_SOCKET")
	if path == "" {
		return
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var done [1]byte
	_, _ = conn.Read(done[:])
}

func TestPeerAuditTokenDistinguishesSameUIDProcesses(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "b-peer-token-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "peer.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := listener.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}

	local, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	localServer, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	localIdentity, err := peerIdentity(localServer)
	localServer.Close()
	if err != nil {
		t.Fatal(err)
	}
	if localIdentity.UID != uint32(os.Geteuid()) || localIdentity.PID != os.Getpid() {
		t.Fatalf("local peer identity = %+v, want UID %d and PID %d", localIdentity, os.Geteuid(), os.Getpid())
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestPeerAuditTokenHelper$")
	cmd.Env = append(os.Environ(), "STAGE2A_PEER_TEST_SOCKET="+path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	childServer, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer childServer.Close()
	childIdentity, err := peerIdentity(childServer)
	if err != nil {
		t.Fatal(err)
	}
	if childIdentity.UID != localIdentity.UID || childIdentity.PID != cmd.Process.Pid ||
		childIdentity.PID == localIdentity.PID || childIdentity.PIDVersion <= 0 {
		t.Fatalf("child peer identity = %+v, local = %+v, child PID = %d", childIdentity, localIdentity, cmd.Process.Pid)
	}
	snapshot, err := observePeerProcess(childServer)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Peer != childIdentity || snapshot.ParentPID != os.Getpid() ||
		snapshot.ParentUID != uint32(os.Geteuid()) ||
		snapshot.StartSeconds == 0 || snapshot.ParentStartSeconds == 0 {
		t.Fatalf("child process snapshot = %+v, want parent PID %d", snapshot, os.Getpid())
	}
	observedChild := v3ObservedChild{
		PID: int64(childIdentity.PID), UID: childIdentity.UID, GID: uint32(os.Getgid()),
		ParentPID: int64(snapshot.ParentPID), ProcessGroup: int64(syscall.Getpgrp()),
		StartSeconds: int64(snapshot.StartSeconds), StartMicros: int64(snapshot.StartMicros),
		LauncherPID: int64(os.Getpid()), LauncherUID: uint32(os.Geteuid()),
		LauncherGID:          uint32(os.Getgid()),
		LauncherStartSeconds: int64(snapshot.ParentStartSeconds),
		LauncherStartMicros:  int64(snapshot.ParentStartMicros),
		CommandDigest:        "sha256:" + strings.Repeat("a", 64),
	}
	_, observedPath, ok := childProcessSnapshot(observedChild.PID)
	if !ok {
		t.Fatal("live child path unavailable")
	}
	member := v3Member{CommandPath: observedPath, CommandDigest: observedChild.CommandDigest}
	if !liveV3Child(observedChild, member) {
		t.Fatal("live observed child/launcher pair refused")
	}
	wrongStart := observedChild
	wrongStart.LauncherStartMicros++
	if liveV3Child(wrongStart, member) {
		t.Fatal("changed launcher start accepted")
	}
	if _, err := childServer.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := observePeerProcess(childServer); err == nil {
		t.Fatal("exited socket peer accepted from stale audit token")
	}
	if liveV3Child(observedChild, member) {
		t.Fatal("exited child accepted from signed observation")
	}
}

//go:build darwin && cgo

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestExitOnFinalSSEByteChild(t *testing.T) {
	path := os.Getenv("STAGE2A_FINAL_SSE_SOCKET")
	if path == "" {
		return
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "POST /v1/messages?beta=true HTTP/1.1\r\nHost: unix\r\nAccept: application/json\r\nAnthropic-Beta: fixture-beta\r\nAnthropic-Dangerous-Direct-Browser-Access: true\r\nAnthropic-Version: 2023-06-01\r\nContent-Type: application/json\r\nX-App: cli\r\nX-Stainless-Retry-Count: 0\r\nX-Api-Key: fixture-key\r\nX-Claude-Code-Session-Id: 11111111-1111-1111-1111-111111111111\r\nContent-Length: %d\r\n\r\n%s", len(prompt), prompt)
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("client received no positive response: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil || !strings.Contains(string(body), "event: message_stop") {
		t.Fatalf("client did not read final SSE event: %v", err)
	}
	os.Exit(0)
}

func TestCompletionSurvivesRealClientExitOnFinalSSEByte(t *testing.T) {
	f := newFixture(t, false, 0, prompt)
	f.ready(t)
	dir, err := os.MkdirTemp("/tmp", "b-final-sse-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "client.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	listener.SetDeadline(time.Now().Add(10 * time.Second))
	parent, _ := observe(dir, os.ModeDir)
	socket, _ := observe(path, os.ModeSocket)
	relay := endpoint{Path: path, Parent: parent, Socket: socket}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(exe, "-test.run=^TestExitOnFinalSSEByteChild$")
	child.Env = append(os.Environ(), "STAGE2A_FINAL_SSE_SOCKET="+path)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if child.ProcessState == nil {
			child.Process.Kill()
			child.Wait()
		}
	}()
	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	peer, err := observePeerProcess(server)
	if err != nil {
		t.Fatal(err)
	}
	currentPeer := func() bool {
		current, err := observePeerProcess(server)
		return err == nil && current == peer
	}
	if !currentPeer() {
		t.Fatal("accepted child was not live")
	}
	input, output := 1, 2
	result := qualificationResult{Model: f.config.Model, Text: "fixture response", Stop: "end_turn"}
	result.Usage.Input, result.Usage.Output = &input, &output
	childExited := false
	completed := false
	writeAndWaitForExit := func(conn *net.UnixConn, prepared preparedHTTP) (httpWrite, error) {
		written, err := writePreparedHTTP(conn, prepared)
		if err != nil {
			return written, err
		}
		if err := child.Wait(); err != nil {
			t.Fatalf("client failed after final SSE byte: %v", err)
		}
		childExited = true
		if currentPeer() {
			t.Fatal("client remained observable after exit")
		}
		return written, nil
	}
	attempted := false
	err = serveWithIngress(context.Background(), server, f.config, relay, &attempted,
		func(model, requestDigest string, out *qualificationResult) error {
			*out = result
			return nil
		}, currentPeer,
		func(requestDigest, promptDigest string, prepared preparedHTTP) (string, error) {
			if !currentPeer() || prepared.SHA256 != digest(prepared.Wire) ||
				prepared.Bytes != len(prepared.Wire) || prepared.Status != http.StatusOK {
				return "", invalid
			}
			return strings.Repeat("3", 64), nil
		},
		func(requestDigest, promptDigest, receipt string, written httpWrite) error {
			if !childExited || receipt != strings.Repeat("3", 64) ||
				written.SHA256 == "" || written.Bytes == 0 || written.Status != http.StatusOK {
				return invalid
			}
			completed = true
			return nil
		}, writeAndWaitForExit)
	if err != nil || !attempted || !completed {
		t.Fatalf("one-shot exit lost B-written completion: attempted=%v completed=%v err=%v", attempted, completed, err)
	}
}

func TestFullRelayEmitsAuthenticatedCompletionAfterOneShotClientExit(t *testing.T) {
	f := newFixture(t, false, 0, prompt)
	f.ready(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(exe, "-test.run=^TestExitOnFinalSSEByteChild$")
	child.Env = append(os.Environ(), "STAGE2A_FINAL_SSE_SOCKET="+f.config.Relay.Path)
	if err := child.Run(); err != nil {
		t.Fatalf("one-shot client did not read complete SSE: %v", err)
	}
	var prewrite prewritePayload
	select {
	case prewrite = <-f.prewritten:
	case <-time.After(3 * time.Second):
		t.Fatal("A prewrite was not requested")
	}
	var completion completionPayload
	select {
	case completion = <-f.completed:
	case err := <-f.done:
		t.Fatalf("B stopped without authenticated completion: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("B did not emit authenticated completion")
	}
	if completion.ResponseWireSHA256 != prewrite.ResponseWireSHA256 ||
		completion.ResponseWireBytes != prewrite.ResponseWireBytes ||
		completion.PrewriteReceipt != strings.Repeat("3", 64) {
		t.Fatal("B completion did not match held prewrite intent")
	}
	derived, err := deriveCompletionSubkey([]byte(strings.Repeat("k", 32)), f.config.Selectors.Reservation)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := completionOriginMAC(derived, completion.completionCore)
	clear(derived)
	if err != nil || mac != completion.CompletionOriginMAC {
		t.Fatal("one-shot response lacked B-origin completion proof")
	}
	select {
	case err := <-f.done:
		t.Fatalf("normal client exit stopped the relay: %v", err)
	default:
	}
}

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

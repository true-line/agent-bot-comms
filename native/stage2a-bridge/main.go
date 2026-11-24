package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"
)

func main() {
	if err := entry(); err != nil {
		fmt.Fprintln(os.Stderr, "Stage 2a bridge stopped: "+err.Error())
		os.Exit(1)
	}
}

func entry() error {
	if len(os.Environ()) != 0 || !slices.Equal(os.Args[1:], []string{"--assignment-fd", "3", "--proof-fd", "4", "--status-fd", "5"}) {
		return fmt.Errorf("invalid fixed invocation")
	}
	for fd := 3; fd <= 5; fd++ {
		syscall.CloseOnExec(fd)
		if syscall.SetNonblock(fd, true) != nil {
			return fmt.Errorf("invalid launch descriptor")
		}
	}
	assignmentFile := os.NewFile(3, "assignment")
	proofFile := os.NewFile(4, "proof")
	statusFile := os.NewFile(5, "status")
	if assignmentFile == nil || proofFile == nil || statusFile == nil {
		return fmt.Errorf("missing launch descriptors")
	}
	defer assignmentFile.Close()
	defer proofFile.Close()
	defer statusFile.Close()
	for _, descriptor := range []*os.File{assignmentFile, proofFile, statusFile} {
		stat, err := descriptor.Stat()
		if err != nil || stat.Mode()&os.ModeNamedPipe == 0 {
			return fmt.Errorf("invalid launch descriptor")
		}
		if descriptor.SetDeadline(deadline()) != nil {
			return fmt.Errorf("launch descriptor deadline unavailable")
		}
	}
	data, err := io.ReadAll(io.LimitReader(assignmentFile, cooperativeFD3MaxBytes+1))
	var probe map[string]json.RawMessage
	if err != nil || len(data) > cooperativeFD3MaxBytes || decode(data, &probe) != nil {
		return fmt.Errorf("invalid launch assignment")
	}
	assignmentFile.Close()
	var version string
	if json.Unmarshal(probe["version"], &version) != nil {
		return fmt.Errorf("invalid launch assignment")
	}
	var bridgeUID uint32
	var v2 assignment
	var v3 v3Authority
	var cooperative cooperativeBridgeAuthority
	switch version {
	case "stage2a-b-assignment/v2":
		if len(data) > 16384 || decode(data, &v2) != nil || v2.validate() != nil {
			return fmt.Errorf("invalid launch assignment")
		}
		bridgeUID = v2.BridgeUID
	case v3Version:
		if len(data) > 16384 {
			return fmt.Errorf("invalid signed launch assignment")
		}
		pin, err := readMachinePin()
		if err != nil {
			return fmt.Errorf("Machine authority pin unavailable")
		}
		v3, err = verifyV3FD3(data, pin, time.Now())
		if err != nil {
			return fmt.Errorf("invalid signed launch assignment")
		}
		bridgeUID = v3.FD3.BridgeUID
	case cooperativeStartVersion:
		pin, err := readMachinePin()
		if err != nil {
			return fmt.Errorf("Machine authority pin unavailable")
		}
		cooperative, err = verifyCooperativeFD3(data, pin, time.Now())
		if err != nil {
			return fmt.Errorf("invalid signed cooperative launch assignment")
		}
		bridgeUID = cooperative.BridgeUID
	default:
		return fmt.Errorf("invalid launch assignment")
	}
	if uint32(os.Getuid()) != bridgeUID || uint32(os.Geteuid()) != bridgeUID ||
		uint32(os.Getgid()) != bridgeUID || uint32(os.Getegid()) != bridgeUID {
		return fmt.Errorf("unexpected bridge identity")
	}
	key, err := io.ReadAll(io.LimitReader(proofFile, 33))
	defer clear(key)
	if err != nil || len(key) != 32 {
		return fmt.Errorf("invalid proof descriptor")
	}
	proofFile.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if version == v3Version {
		return runV3(ctx, v3, key, statusFile, peerUID)
	}
	if version == cooperativeStartVersion {
		return runCooperative(ctx, cooperative, key, statusFile, peerUID)
	}
	return run(ctx, v2, key, statusFile, peerUID, observePeerProcess, writePreparedHTTP)
}

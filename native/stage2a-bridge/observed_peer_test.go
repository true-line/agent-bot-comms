package main

import (
	"net"
	"testing"
)

func TestObservedPeerRequiresSameLiveProcessAndParent(t *testing.T) {
	snapshot := peerProcessSnapshot{
		Peer:         peerProcessIdentity{UID: 303, PID: 4101, PIDVersion: 7},
		StartSeconds: 1795500000, StartMicros: 123456,
		ParentPID: 4001, ParentUID: 303,
		ParentStartSeconds: 1795499999, ParentStartMicros: 654321,
	}
	accepted, err := observedPeerFromSnapshot(snapshot, 303)
	if err != nil || accepted.PID != 4101 || accepted.ParentPID != 4001 {
		t.Fatalf("live stock peer refused: %v", err)
	}
	// A different CLI socket, reused PID, or restarted parent changes the
	// signed nine-field peer even when UID remains the same.
	for name, change := range map[string]func(*peerProcessSnapshot){
		"sibling_cli":     func(s *peerProcessSnapshot) { s.Peer.PID++ },
		"reused_pid":      func(s *peerProcessSnapshot) { s.Peer.PIDVersion++ },
		"restarted_child": func(s *peerProcessSnapshot) { s.ParentStartSeconds++ },
		"wrong_uid":       func(s *peerProcessSnapshot) { s.Peer.UID++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := snapshot
			change(&changed)
			peer, err := observedPeerFromSnapshot(changed, 303)
			if err == nil && peer == accepted {
				t.Fatal("changed socket/process kept accepted identity")
			}
		})
	}
	if observedPeerStillCurrent(nil, accepted, 303,
		func(*net.UnixConn) (peerProcessSnapshot, error) { return snapshot, nil }) {
		t.Fatal("missing accepted Unix connection passed live check")
	}
}

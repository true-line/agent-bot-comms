package main

import "net"

func observedPeerFromSnapshot(snapshot peerProcessSnapshot, runnerUID uint32) (observedPeer, error) {
	if !validRelayPeer(snapshot, runnerUID) {
		return observedPeer{}, invalid
	}
	return observedPeer{
		UID: snapshot.Peer.UID, PID: uint32(snapshot.Peer.PID),
		PIDVersion:   uint64(snapshot.Peer.PIDVersion),
		StartSeconds: snapshot.StartSeconds, StartMicros: uint32(snapshot.StartMicros),
		ParentPID: uint32(snapshot.ParentPID), ParentUID: snapshot.ParentUID,
		ParentStartSeconds: snapshot.ParentStartSeconds,
		ParentStartMicros:  uint32(snapshot.ParentStartMicros),
	}, nil
}

// Compare a fresh audit-token/process-table view of the same accepted socket.
// Machine separately joins this nine-field peer to its signed child record.
func observedPeerStillCurrent(conn *net.UnixConn, accepted observedPeer,
	runnerUID uint32, capture capturePeer) bool {
	if conn == nil || capture == nil {
		return false
	}
	fresh, err := capture(conn)
	if err != nil {
		return false
	}
	peer, err := observedPeerFromSnapshot(fresh, runnerUID)
	return err == nil && peer == accepted
}

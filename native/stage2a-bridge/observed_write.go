package main

import (
	"net"
	"time"
)

// The final proof/stop/peer check runs inside the writer immediately before
// the first byte. Once that gate passes, a bounded full write may finish
// after the A authorization and prewrite proof expire.
func writePreparedObservedHTTP(conn *net.UnixConn, prepared preparedHTTP,
	beforeFirstByte func() bool) (httpWrite, error) {
	if conn == nil || beforeFirstByte == nil || prepared.Status != 200 ||
		prepared.Bytes <= 0 || len(prepared.Wire) != prepared.Bytes ||
		prepared.SHA256 != digest(prepared.Wire) ||
		conn.SetWriteDeadline(deadline()) != nil || !beforeFirstByte() {
		return httpWrite{}, invalid
	}
	started := time.Now().UTC()
	for written := 0; written < len(prepared.Wire); {
		n, err := conn.Write(prepared.Wire[written:])
		written += n
		if err != nil || n == 0 {
			return httpWrite{}, invalid
		}
	}
	return httpWrite{SHA256: prepared.SHA256, Bytes: prepared.Bytes,
		Status: prepared.Status, StartedAt: started,
		CompletedAt: time.Now().UTC()}, nil
}

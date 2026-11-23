package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"
)

// This cooperative route authenticates the Machine-assigned B process,
// reports its bound relay to A, then verifies A's two-member policy over the
// same H broker connection. A later signed Ready/live-peer exchange must
// arrive before any R HTTP request can be forwarded; ingress stays closed.
func runCooperative(ctx context.Context, authority cooperativeBridgeAuthority,
	key []byte, status io.WriteCloser, check checkPeer) (runErr error) {
	defer clear(key)
	brokerEndpoint, err := cooperativeRuntimeEndpoint(authority.BrokerRecord, true)
	if err != nil {
		return errors.New("cooperative broker endpoint rejected")
	}
	relayEndpoint, err := cooperativeRuntimeEndpoint(authority.RelayRecord, false)
	if err != nil {
		return errors.New("cooperative relay endpoint rejected")
	}
	b, err := openBroker(ctx, assignment{Broker: brokerEndpoint, HQUID: authority.HQUID}, check)
	if err != nil {
		return errors.New("cooperative broker identity or connection rejected")
	}
	defer b.conn.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-b.dead:
			cancel()
		case <-ctx.Done():
		}
	}()
	receipt, err := b.bindCooperative(ctx, authority, key, brokerEndpoint)
	if err != nil {
		return errors.New("cooperative broker bind rejected")
	}
	listener, relay, cleanup, err := listenRelay(relayEndpoint)
	if err != nil {
		return errors.Join(errors.New("cooperative relay endpoint rejected"), err)
	}
	defer func() { runErr = errors.Join(runErr, cleanup()) }()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	if ctx.Err() != nil || !cooperativeEndpointCurrent(authority.BrokerRecord, brokerEndpoint) ||
		!cooperativeEndpointCurrent(authority.RelayRecord, relay) ||
		!time.Now().Before(authority.Expires) {
		return invalid
	}
	currentRelay, err := cooperativeRuntimeEndpoint(authority.RelayRecord, true)
	if err != nil || currentRelay != relay {
		return invalid
	}
	if json.NewEncoder(status).Encode(struct {
		Digest string   `json:"bind_receipt_sha256"`
		Socket identity `json:"relay_socket"`
	}{receipt, relay.Socket}) != nil || status.Close() != nil {
		return errors.New("could not report cooperative relay readiness")
	}
	pin, err := readMachinePin()
	if err != nil {
		return errors.New("Machine authority pin unavailable")
	}
	policy, err := b.cooperativeMemberPolicy(ctx, authority, pin, brokerEndpoint, relayEndpoint)
	if err != nil || !time.Now().Before(policy.FD3.Expires) {
		return errors.New("cooperative signed member policy rejected")
	}
	for {
		if ctx.Err() != nil {
			return nil
		}
		if !cooperativeEndpointCurrent(authority.BrokerRecord, brokerEndpoint) ||
			!cooperativeEndpointCurrent(authority.RelayRecord, relay) ||
			!time.Now().Before(policy.FD3.Expires) {
			return errors.New("cooperative authority or endpoint expired")
		}
		if listener.SetDeadline(time.Now().Add(250*time.Millisecond)) != nil {
			return errors.New("cooperative relay listener deadline unavailable")
		}
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			return errors.New("cooperative relay listener failed")
		}
		conn.Close()
	}
}

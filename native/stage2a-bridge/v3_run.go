package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"
)

// The signed v3 FD3 and HMAC bind establish one B process and one relay
// listener. They do not observe either ACP child or a later CLI peer. Until
// the separately signed two-member arm/Ready and per-request live-peer path
// are installed, every relay connection is closed without HTTP ingress.
func runV3(ctx context.Context, authority v3Authority, key []byte,
	status io.WriteCloser, check checkPeer) (runErr error) {
	defer clear(key)
	f := authority.FD3
	b, err := openBroker(ctx, assignment{Broker: f.Broker, HQUID: f.HQUID}, check)
	if err != nil {
		return errors.New("broker identity or connection rejected")
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
	receipt, err := b.bindV3(ctx, f, key)
	if err != nil {
		return errors.New("broker v3 bind rejected")
	}
	listener, relay, cleanup, err := listenRelay(f.Relay)
	if err != nil {
		return errors.Join(errors.New("relay endpoint rejected"), err)
	}
	defer func() { runErr = errors.Join(runErr, cleanup()) }()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	if ctx.Err() != nil || !f.Broker.current() || !relay.current() {
		return invalid
	}
	if json.NewEncoder(status).Encode(struct {
		Digest string   `json:"bind_receipt_sha256"`
		Socket identity `json:"relay_socket"`
	}{receipt, relay.Socket}) != nil || status.Close() != nil {
		return errors.New("could not report relay readiness")
	}
	for {
		if listener.SetDeadline(time.Now().Add(250*time.Millisecond)) != nil {
			return errors.New("relay listener deadline unavailable")
		}
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				if !relay.current() || !f.Broker.current() || !time.Now().Before(f.Expires) {
					return errors.New("v3 bridge authority or endpoint expired")
				}
				continue
			}
			return errors.New("relay listener failed")
		}
		conn.Close() // No per-member Ready or live CLI proof exists yet.
	}
}

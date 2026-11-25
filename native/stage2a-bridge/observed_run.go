package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"
)

// The observed route requires three H→Machine authority transitions. H owns
// the live A epoch, B generation, stop, claim, prewrite and completed-run
// checks behind these calls. B independently checks signed replies and its
// current socket/peer at each transition; it cannot infer live A state from
// a startup snapshot.
type observedAuthorityGate interface {
	authorizeObserved(context.Context, observedIngressCore, []byte, observedAuthority,
		func() bool, *bool) (observedAuthorized, error)
	prewriteObserved(context.Context, observedPrewrite, observedIngressCore,
		observedAuthorized, observedAuthority, func() bool, *bool) (observedPrewriteReply, error)
	completeObserved(context.Context, observedCompletionPayload, func() bool) error
}

func runObserved(ctx context.Context, authority observedAuthority, rawFD4 []byte,
	status io.WriteCloser, check checkPeer, capture capturePeer) (runErr error) {
	defer clear(rawFD4)
	config := authority.FD3
	if config.Selectors.validate() != nil ||
		config.LocalTest.validate(config.Selectors.InstallationID, config.Selectors.StartID) != nil ||
		capture == nil || status == nil ||
		!time.Now().Before(config.Expires) {
		return invalid
	}
	brokerConfig := assignment{Broker: config.Broker, HQUID: config.HQUID}
	b, err := openBroker(ctx, brokerConfig, check)
	if err != nil {
		return errors.New("observed broker identity or connection rejected")
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
	ingressKey, err := observedSubkey(rawFD4, config.Selectors.ReservationDigest,
		observedIngressKeyContext)
	if err != nil {
		return invalid
	}
	defer clear(ingressKey)
	completionKey, err := observedSubkey(rawFD4, config.Selectors.ReservationDigest,
		observedCompleteKeyContext)
	if err != nil {
		return invalid
	}
	defer clear(completionKey)
	bindInput := observedBindInput{
		Selectors: config.Selectors, Epoch: config.Epoch,
		BridgeUID: config.BridgeUID, BrokerPath: config.Broker.Path,
		RunnerAccount:          config.LocalTest.RunnerAccount,
		ChildCWDEmitted:        config.LocalTest.ExpectedChildCWDEmitted,
		BodyProfile:            config.LocalTest.BodyProfile,
		StaticProjectionSHA256: config.LocalTest.StaticProjectionSHA256,
		OwnerPromptSHA256:      config.LocalTest.OwnerPromptSHA256,
		Expires:                config.Expires,
	}
	receipt, err := b.bindObserved(ctx, bindInput, rawFD4, config.Broker.current)
	if err != nil {
		return errors.New("observed broker bind rejected")
	}
	listener, relay, cleanup, err := listenRelay(config.Relay)
	if err != nil {
		return errors.Join(errors.New("observed relay endpoint rejected"), err)
	}
	defer func() { runErr = errors.Join(runErr, cleanup()) }()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	if ctx.Err() != nil || !config.Broker.current() || !relay.current() {
		return invalid
	}
	if json.NewEncoder(status).Encode(struct {
		Digest string   `json:"bind_receipt_sha256"`
		Socket identity `json:"relay_socket"`
	}{receipt, relay.Socket}) != nil || status.Close() != nil {
		return errors.New("observed relay readiness unavailable")
	}
	var sequence observedSequence
	ingressAttempted, prewriteAttempted, completionAttempted := false, false, false
	for {
		if ctx.Err() != nil {
			select {
			case <-b.dead:
				return errors.New("observed broker disconnected")
			default:
				return nil
			}
		}
		if !time.Now().Before(config.Expires) || !config.Broker.current() || !relay.current() {
			return invalid
		}
		if err := listener.SetDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
			return invalid
		}
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				select {
				case <-b.dead:
					return errors.New("observed broker disconnected")
				default:
					return nil
				}
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			return err
		}
		if !config.Broker.current() || !relay.current() ||
			!peerMatches(conn, config.RunnerUID, check) {
			conn.Close()
			continue
		}
		snapshot, err := capture(conn)
		peer, peerErr := observedPeerFromSnapshot(snapshot, config.RunnerUID)
		if err != nil || peerErr != nil {
			conn.Close()
			continue
		}
		stopConn := context.AfterFunc(ctx, func() { conn.Close() })
		err = serveObserved(ctx, conn, b, authority, relay, receipt, peer, capture,
			ingressKey, completionKey, &sequence, &ingressAttempted,
			&prewriteAttempted, &completionAttempted, writePreparedObservedHTTP)
		stopConn()
		conn.Close()
		if err != nil {
			return err
		}
	}
}

func observedAttemptID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return "attempt." + hex.EncodeToString(random[:]), nil
}

func serveObserved(ctx context.Context, conn *net.UnixConn, gate observedAuthorityGate,
	authority observedAuthority, relay endpoint, bindReceipt string,
	peer observedPeer, capture capturePeer, ingressKey, completionKey []byte,
	sequence *observedSequence, ingressAttempted, prewriteAttempted,
	completionAttempted *bool,
	writeSuccess func(*net.UnixConn, preparedHTTP, func() bool) (httpWrite, error)) error {
	config := authority.FD3
	current := func() bool {
		return ctx.Err() == nil && time.Now().Before(config.Expires) &&
			config.Broker.current() && relay.current() &&
			observedPeerStillCurrent(conn, peer, config.RunnerUID, capture)
	}
	if !current() || conn.SetReadDeadline(deadline()) != nil {
		return invalid
	}
	req, err := readRequest(conn)
	if err != nil {
		writeHTTP(conn, 400, "text/plain", nil)
		return nil
	}
	if req.ContentLength < 1 || req.ContentLength > maxBody {
		writeHTTP(conn, 422, "text/plain", nil)
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(req.Body, req.ContentLength+1))
	if err != nil || int64(len(data)) != req.ContentLength || !current() {
		writeHTTP(conn, 422, "text/plain", nil)
		return nil
	}
	inspected, err := classifyObservedRequest(req, data, authority)
	if err != nil || sequence.acceptFrom(inspected.Class, peer) != nil {
		writeHTTP(conn, 422, "text/plain", nil)
		return nil
	}
	if inspected.Class != observedTarget {
		writeHTTP(conn, 422, "text/plain", nil)
		return nil
	}
	if *ingressAttempted {
		writeHTTP(conn, 409, "text/plain", nil)
		return nil
	}
	if gate == nil {
		return invalid
	}
	attemptID, err := observedAttemptID()
	if err != nil || !current() {
		return invalid
	}
	peerBytes, err := canonicalJSONValue(peer)
	if err != nil {
		return invalid
	}
	core := observedIngressCore{
		Schema: "stage2a-observed-body-local-test-ingress/v1",
		Kind:   "observed-body-local-test-ingress", Selectors: config.Selectors,
		BindReceiptSHA256: bindReceipt, Peer: peer, PeerSHA256: digest(peerBytes),
		ObservedBodySHA256:     inspected.Body.BodySHA256,
		ObservedHeadersSHA256:  inspected.HeadersSHA256,
		StaticProjectionSHA256: config.LocalTest.StaticProjectionSHA256,
		ObservedBriefSHA256:    inspected.Body.BriefSHA256,
		OwnerPromptSHA256:      config.LocalTest.OwnerPromptSHA256,
		BodyProfile:            config.LocalTest.BodyProfile,
		DigestKind:             "observed-stock-body/v1",
		TargetReceivedAt:       time.Now().UTC().Format(time.RFC3339Nano),
		AttemptID:              attemptID,
	}
	authorized, err := gate.authorizeObserved(ctx, core, ingressKey, authority,
		current, ingressAttempted)
	if err != nil || !current() {
		writeHTTP(conn, 503, "text/plain", nil)
		return invalid
	}
	prepared, err := prepareObservedResponse(authorized.Provider, config.LocalTest.Model)
	if err != nil || !current() {
		return invalid
	}
	prewrite, err := buildObservedPrewrite(core, authorized, prepared, time.Now())
	if err != nil || !current() {
		return invalid
	}
	// Recheck the A authorization at the last B-controlled moment before
	// Machine's prewrite gate. Machine checks it again before issuing receipt.
	if _, err := verifyObservedAuthorization(authorized.Result.observedAuthorizationReply,
		authority.Pin[:], core, config.Expires, time.Now()); err != nil {
		return invalid
	}
	prewriteReply, err := gate.prewriteObserved(ctx, prewrite, core, authorized,
		authority, current, prewriteAttempted)
	if err != nil || !current() {
		return invalid
	}
	// A successful one-use prewrite may outlive its A authorization during
	// the bounded full write. Stop, sockets and live peer remain checked.
	if ctx.Err() != nil || !config.Broker.current() || !relay.current() ||
		!observedPeerStillCurrent(conn, peer, config.RunnerUID, capture) ||
		verifyObservedPrewriteProof(prewriteReply, prewrite, core,
			authorized.Result.observedAuthorizationReply, authority, time.Now()) != nil {
		return invalid
	}
	written, err := writeSuccess(conn, prepared, func() bool {
		return ctx.Err() == nil && config.Broker.current() && relay.current() &&
			observedPeerStillCurrent(conn, peer, config.RunnerUID, capture) &&
			verifyObservedPrewriteProof(prewriteReply, prewrite, core,
				authorized.Result.observedAuthorizationReply, authority, time.Now()) == nil
	})
	if err != nil || ctx.Err() != nil || !config.Broker.current() || !relay.current() {
		return errors.New("observed response write failed")
	}
	completion, err := buildObservedCompletion(prewrite, prewriteReply.PrewriteReceipt, written)
	if err != nil {
		return invalid
	}
	sealed, err := sealObservedCompletion(completion, completionKey, completionAttempted)
	if err != nil {
		return invalid
	}
	if gate.completeObserved(ctx, sealed, func() bool {
		return ctx.Err() == nil && config.Broker.current() && relay.current()
	}) != nil {
		return errors.New("observed completion acknowledgement rejected")
	}
	return nil
}

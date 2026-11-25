package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func observedTestEndpoint(t *testing.T, dir, name string) (*net.UnixListener, endpoint) {
	t.Helper()
	path := filepath.Join(dir, name)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	parent, err := observe(dir, os.ModeDir)
	if err != nil {
		t.Fatal(err)
	}
	socket, err := observe(path, os.ModeSocket)
	if err != nil {
		t.Fatal(err)
	}
	return listener, endpoint{Path: path, Parent: parent, Socket: socket}
}

func observedRawRequest(fixed map[string]string, body []byte) []byte {
	req := observedClassifyRequest(fixed, body)
	var wire bytes.Buffer
	fmt.Fprint(&wire, "POST /v1/messages?beta=true HTTP/1.1\r\nHost: fixture.invalid\r\n")
	for name, values := range req.Header {
		fmt.Fprintf(&wire, "%s: %s\r\n", name, values[0])
	}
	fmt.Fprint(&wire, "\r\n")
	wire.Write(body)
	return wire.Bytes()
}

func TestObservedAncillaryRefusedLocallyBeforeBroker(t *testing.T) {
	authority, _, ancillary := observedClassificationFixture(t)
	dir, err := os.MkdirTemp("/tmp", "observed-route-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	_, brokerEndpoint := observedTestEndpoint(t, dir, "broker.sock")
	listener, relay := observedTestEndpoint(t, dir, "relay.sock")
	authority.FD3.Broker = brokerEndpoint
	authority.FD3.RunnerUID = 303
	authority.FD3.Expires = time.Now().Add(10 * time.Second)
	snapshot := peerProcessSnapshot{
		Peer:         peerProcessIdentity{UID: 303, PID: 4101, PIDVersion: 7},
		StartSeconds: 1795500000, StartMicros: 123456,
		ParentPID: 4001, ParentUID: 303,
		ParentStartSeconds: 1795499999, ParentStartMicros: 654321,
	}
	peer, err := observedPeerFromSnapshot(snapshot, 303)
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.SetDeadline(time.Now().Add(3*time.Second)) != nil {
		t.Fatal("client deadline unavailable")
	}
	accepted, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	request := observedRawRequest(authority.FD3.LocalTest.AncillaryProfile.FirstHeaderShape.RequiredFixed,
		ancillary)
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	var sequence observedSequence
	var pending observedPendingCompletion
	ingress, prewrite, complete := false, false, false
	// nil broker proves this path performs no H call at all.
	if err := serveObserved(context.Background(), accepted, nil, authority, relay,
		digest([]byte("bind receipt")), peer,
		func(*net.UnixConn) (peerProcessSnapshot, error) { return snapshot, nil },
		nil, nil, &sequence, &pending, &ingress, &prewrite, &complete, nil); err != nil {
		t.Fatalf("ancillary local refusal failed: %v", err)
	}
	accepted.Close()
	response, err := io.ReadAll(client)
	if err != nil || !strings.HasPrefix(string(response), "HTTP/1.1 422 ") ||
		ingress || prewrite || complete || !sequence.ancillaryA || sequence.target {
		t.Fatalf("ancillary reached broker or returned wrong status: %q %v", response, err)
	}
}

func runObservedTargetRoute(t *testing.T, mode string) {
	t.Helper()
	authority, target, ancillary := observedClassificationFixture(t)
	selectors := observedSelectors{
		InstallationID: "fixture.installation",
		StartID:        "st_" + strings.Repeat("1", 24), LaunchID: "ln_" + strings.Repeat("2", 24),
		PlanID: "plan.fixture", PlanDigest: strings.Repeat("3", 64),
		ReservationDigest:     digest([]byte("reservation")),
		AssignmentEnvelopeSHA: digest([]byte("assignment")),
		AuthorityEnvelopeSHA:  digest([]byte("authority")),
		MemberSelectorsSHA256: digest([]byte("member selectors")),
	}
	authority.FD3.Selectors = selectors
	authority.FD3.Epoch = strings.Repeat("4", 64)
	authority.FD3.RunnerUID = 303
	authority.FD3.Expires = time.Now().Add(30 * time.Second)
	responseText := "fixture response"
	authority.ResponseTextSHA256 = digest([]byte(responseText))
	fixtureConfig, err := canonicalJSONValue(map[string]any{
		"schema": "stage2a-observed-body-local-test-fixture/v1",
		"model":  authority.FD3.LocalTest.Model, "response_text": responseText,
	})
	if err != nil {
		t.Fatal(err)
	}
	authority.FD3.LocalTest.FixtureConfigSHA256 = digest(fixtureConfig)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x88}, 32))
	copy(authority.Pin[:], privateKey.Public().(ed25519.PublicKey))
	dir, err := os.MkdirTemp("/tmp", "observed-full-route-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	hListener, hEndpoint := observedTestEndpoint(t, dir, "broker.sock")
	rListener, rEndpoint := observedTestEndpoint(t, dir, "relay.sock")
	authority.FD3.Broker = hEndpoint
	authority.FD3.HQUID = hEndpoint.Parent.UID
	snapshot := peerProcessSnapshot{
		Peer:         peerProcessIdentity{UID: 303, PID: 4101, PIDVersion: 7},
		StartSeconds: 1795500000, StartMicros: 123456,
		ParentPID: 4001, ParentUID: 303,
		ParentStartSeconds: 1795499999, ParentStartMicros: 654321,
	}
	peer, err := observedPeerFromSnapshot(snapshot, 303)
	if err != nil {
		t.Fatal(err)
	}
	rawFD4 := bytes.Repeat([]byte{0x42}, 32)
	ingressKey, err := observedSubkey(rawFD4, selectors.ReservationDigest, observedIngressKeyContext)
	if err != nil {
		t.Fatal(err)
	}
	completionKey, err := observedSubkey(rawFD4, selectors.ReservationDigest, observedCompleteKeyContext)
	if err != nil {
		t.Fatal(err)
	}
	hIngressKey := append([]byte(nil), ingressKey...)
	hCompletionKey := append([]byte(nil), completionKey...)
	hDone := make(chan error, 1)
	releaseH := make(chan struct{})
	go func() {
		conn, err := hListener.AcceptUnix()
		if err != nil {
			hDone <- err
			return
		}
		defer conn.Close()
		scan := bufio.NewScanner(conn)
		scan.Buffer(make([]byte, 4096), 32768)
		ops := []string{observedIngressOp, observedPrewriteOp, observedCompleteOp}
		if mode == "invalid-auth" || mode == "expired-auth" {
			ops = ops[:1]
		} else if mode == "write-failure" || mode == "stopped-before-write" ||
			mode == "invalid-proof" || mode == "expired-proof" || mode == "wrong-core-proof" ||
			mode == "expired-before-write" || mode == "bare-receipt" ||
			mode == "wrong-epoch-proof" || mode == "missing-second" ||
			mode == "wrong-peer-second" || mode == "late-second" {
			ops = ops[:2]
		}
		for index, op := range ops {
			if !scan.Scan() {
				hDone <- invalid
				return
			}
			var request struct {
				ID      string          `json:"id"`
				Op      string          `json:"op"`
				Payload json.RawMessage `json:"payload"`
			}
			if decode(scan.Bytes(), &request) != nil || request.Op != op {
				hDone <- invalid
				return
			}
			var result any
			switch index {
			case 0:
				var ingress observedIngressPayload
				if decode(request.Payload, &ingress) != nil {
					hDone <- invalid
					return
				}
				mac, _ := observedOriginMAC(hIngressKey, observedIngressOriginContext, ingress.Core)
				if ingress.IngressOriginMAC != mac || ingress.Core.ObservedBodySHA256 != digest(target) {
					hDone <- invalid
					return
				}
				coreBytes, _ := canonicalJSONValue(ingress.Core)
				issued := time.Now().UTC().Add(-time.Second)
				if mode == "expired-auth" {
					issued = time.Now().UTC().Add(-25 * time.Second)
				}
				payload := map[string]any{
					"schema":    "agent-bot-machine/stage2a-observed-body-local-test-ingress-authorization/v1",
					"kind":      "observed-body-local-test-ingress-authorization",
					"selectors": selectors, "ingress_core_sha256": digest(coreBytes),
					"provider_claim_sha256": digest([]byte("spent claim")),
					"issued_at":             issued.Format(time.RFC3339Nano),
					"expires_at":            issued.Add(20 * time.Second).Format(time.RFC3339Nano),
				}
				payloadBytes, _ := canonicalJSONValue(payload)
				purpose := observedAuthorizationPurpose
				envelopeBytes, _ := canonicalJSONValue(map[string]any{
					"schema_version": 1, "purpose": purpose,
					"issuer_public_key_base64url": base64.RawURLEncoding.EncodeToString(authority.Pin[:]),
					"payload_sha256":              digest(payloadBytes),
					"payload_base64url":           base64.RawURLEncoding.EncodeToString(payloadBytes),
					"signature_base64url": base64.RawURLEncoding.EncodeToString(ed25519.Sign(
						privateKey, append([]byte(purpose+"\x00"), payloadBytes...))),
				})
				provider := observedProviderResponse{Mode: "observed-body-local-test/v1",
					Model:              authority.FD3.LocalTest.Model,
					ObservedBodySHA256: ingress.Core.ObservedBodySHA256,
					ResponseText:       responseText, ResponseSHA256: authority.ResponseTextSHA256,
					Invocation: 1}
				providerRequest, _ := canonicalJSONValue(map[string]any{
					"mode": provider.Mode, "model": provider.Model,
					"observed_body_sha256": provider.ObservedBodySHA256,
				})
				providerResponse, _ := canonicalJSONValue(provider)
				ingressResult := observedIngressResult{
					observedAuthorizationReply: observedAuthorizationReply{
						Envelope:    base64.RawURLEncoding.EncodeToString(envelopeBytes),
						EnvelopeSHA: digest(envelopeBytes)},
					IngressCoreSHA256: digest(coreBytes), Provider: provider,
					ProviderRequestBodySHA256:  digest(providerRequest),
					ProviderResponseBodySHA256: digest(providerResponse),
				}
				if mode == "invalid-auth" {
					ingressResult.EnvelopeSHA = digest([]byte("forged authorization digest"))
				}
				result = ingressResult
			case 1:
				var prewrite observedPrewrite
				if decode(request.Payload, &prewrite) != nil || prewrite.ObservedBodySHA256 != digest(target) {
					hDone <- invalid
					return
				}
				receipt := strings.Repeat("a", 64)
				if mode == "bare-receipt" {
					result = map[string]any{"prewrite_receipt": receipt}
					break
				}
				prewriteBytes, _ := canonicalJSONValue(prewrite)
				issued := time.Now().UTC().Add(-100 * time.Millisecond)
				expires := issued.Add(10 * time.Second)
				if mode == "expired-before-write" {
					expires = time.Now().UTC().Add(2 * time.Second)
				}
				if mode == "expired-proof" {
					issued = time.Now().UTC().Add(-500 * time.Millisecond)
					expires = time.Now().UTC().Add(-100 * time.Millisecond)
				}
				coreSHA := digest(prewriteBytes)
				if mode == "wrong-core-proof" {
					coreSHA = digest([]byte("other prewrite"))
				}
				proofPayload := map[string]any{
					"schema":         "agent-bot-machine/stage2a-observed-body-local-test-prewrite-acceptance/v1",
					"kind":           "observed-body-local-test-prewrite-acceptance",
					"schema_version": 1,
					"selectors":      selectors, "hq_epoch": authority.FD3.Epoch,
					"authorization_envelope_sha256": prewrite.AuthorizationEnvelopeSHA256,
					"prewrite_core_sha256":          coreSHA, "prewrite_receipt": receipt,
					"issued_at":  issued.Format(time.RFC3339Nano),
					"expires_at": expires.Format(time.RFC3339Nano),
				}
				if mode == "wrong-epoch-proof" {
					proofPayload["hq_epoch"] = strings.Repeat("5", 64)
				}
				proofBytes, _ := canonicalJSONValue(proofPayload)
				purpose := observedPrewriteAcceptancePurpose
				envelopeBytes, _ := canonicalJSONValue(map[string]any{
					"schema_version": 1, "purpose": purpose,
					"issuer_public_key_base64url": base64.RawURLEncoding.EncodeToString(authority.Pin[:]),
					"payload_sha256":              digest(proofBytes),
					"payload_base64url":           base64.RawURLEncoding.EncodeToString(proofBytes),
					"signature_base64url": base64.RawURLEncoding.EncodeToString(ed25519.Sign(
						privateKey, append([]byte(purpose+"\x00"), proofBytes...))),
				})
				proofSHA := digest(envelopeBytes)
				if mode == "invalid-proof" {
					proofSHA = digest([]byte("forged prewrite proof"))
				}
				result = observedPrewriteReply{PrewriteReceipt: receipt,
					ProofEnvelope:       base64.RawURLEncoding.EncodeToString(envelopeBytes),
					ProofEnvelopeSHA256: proofSHA}
			case 2:
				var completion observedCompletionPayload
				if err := decode(request.Payload, &completion); err != nil {
					hDone <- fmt.Errorf("completion decode: %w", err)
					return
				}
				mac, _ := observedOriginMAC(hCompletionKey, observedCompleteOriginContext, completion.Core)
				if completion.CompletionOriginMAC != mac ||
					completion.Core.ResponseWireBytes < 800 {
					hDone <- fmt.Errorf("completion MAC/length: mac=%t bytes=%d", completion.CompletionOriginMAC == mac, completion.Core.ResponseWireBytes)
					return
				}
				coreBytes, _ := canonicalJSONValue(completion.Core)
				result = map[string]any{"accepted": true, "selectors": selectors,
					"observed_body_sha256":          digest(target),
					"authorization_envelope_sha256": completion.Core.AuthorizationEnvelopeSHA256,
					"completion_core_sha256":        digest(coreBytes),
					"completed_run_sha256":          digest([]byte("completed run"))}
				if mode == "bad-ack" {
					result.(map[string]any)["completion_core_sha256"] = digest([]byte("wrong core"))
				}
			}
			if err := json.NewEncoder(conn).Encode(map[string]any{
				"id": request.ID, "ok": true, "result": result,
			}); err != nil {
				hDone <- err
				return
			}
			if mode == "stopped-before-write" && index == 1 {
				hListener.Close()
			}
		}
		hDone <- nil
		<-releaseH
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b, err := openBroker(ctx, assignment{Broker: hEndpoint, HQUID: hEndpoint.Parent.UID},
		func(*net.UnixConn) (uint32, error) { return hEndpoint.Parent.UID, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer b.conn.Close()
	client, err := net.DialUnix("unix", nil, rListener.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	accepted, err := rListener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	if _, err := client.Write(observedRawRequest(authority.FD3.LocalTest.HeaderShape.RequiredFixed,
		target)); err != nil {
		t.Fatal(err)
	}
	sequence := observedSequence{ancillaryA: true}
	if mode != "target-before-second" && mode != "missing-second" &&
		mode != "wrong-peer-second" && mode != "late-second" {
		sequence.ancillaryB = true
	}
	var pending observedPendingCompletion
	ingressAttempted, prewriteAttempted, completionAttempted := false, false, false
	writeSuccess := writePreparedObservedHTTP
	if mode == "write-failure" {
		writeSuccess = func(*net.UnixConn, preparedHTTP, func() bool) (httpWrite, error) {
			return httpWrite{}, invalid
		}
	} else if mode == "expired-before-write" {
		writeSuccess = func(conn *net.UnixConn, prepared preparedHTTP,
			beforeFirstByte func() bool) (httpWrite, error) {
			time.Sleep(2100 * time.Millisecond)
			return writePreparedObservedHTTP(conn, prepared, beforeFirstByte)
		}
	}
	routeErr := serveObserved(ctx, accepted, b, authority, rEndpoint,
		digest([]byte("bind receipt")), peer,
		func(*net.UnixConn) (peerProcessSnapshot, error) { return snapshot, nil },
		ingressKey, completionKey, &sequence, &pending, &ingressAttempted,
		&prewriteAttempted, &completionAttempted, writeSuccess)
	accepted.Close()
	wire, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	if mode == "target-before-second" || mode == "missing-second" ||
		mode == "wrong-peer-second" || mode == "late-second" {
		if routeErr != nil || !strings.HasPrefix(string(wire), "HTTP/1.1 200 ") ||
			!bytes.Contains(wire, []byte("event: message_stop\n")) ||
			!pending.Ready || !pending.Deadline.After(time.Now()) ||
			completionAttempted || sequence.complete() {
			t.Fatalf("target alone completed or failed: %v, %q", routeErr, wire)
		}
		if mode != "missing-second" {
			if mode == "late-second" {
				pending.Deadline = time.Now().Add(-time.Millisecond)
			}
			secondClient, err := net.DialUnix("unix", nil, rListener.Addr().(*net.UnixAddr))
			if err != nil {
				t.Fatal(err)
			}
			secondClient.SetDeadline(time.Now().Add(5 * time.Second))
			secondConn, err := rListener.AcceptUnix()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := secondClient.Write(observedRawRequest(
				authority.FD3.LocalTest.AncillaryProfile.SecondHeaderShape.RequiredFixed,
				ancillary)); err != nil {
				t.Fatal(err)
			}
			secondSnapshot := snapshot
			if mode == "wrong-peer-second" {
				secondSnapshot.Peer.PID++
				secondSnapshot.Peer.PIDVersion++
			}
			secondPeer, err := observedPeerFromSnapshot(secondSnapshot, 303)
			if err != nil {
				t.Fatal(err)
			}
			secondErr := serveObserved(ctx, secondConn, b, authority, rEndpoint,
				digest([]byte("bind receipt")), secondPeer,
				func(*net.UnixConn) (peerProcessSnapshot, error) { return secondSnapshot, nil },
				ingressKey, completionKey, &sequence, &pending, &ingressAttempted,
				&prewriteAttempted, &completionAttempted, writePreparedObservedHTTP)
			secondConn.Close()
			secondWire, err := io.ReadAll(secondClient)
			secondClient.Close()
			if err != nil {
				t.Fatal(err)
			}
			if mode == "target-before-second" {
				if secondErr != nil || !strings.HasPrefix(string(secondWire), "HTTP/1.1 422 ") ||
					!completionAttempted || !sequence.complete() || pending.Ready {
					t.Fatalf("valid postwrite second did not complete: %v, %q", secondErr, secondWire)
				}
			} else if completionAttempted || sequence.complete() ||
				(mode == "wrong-peer-second" &&
					(secondErr != nil || !strings.HasPrefix(string(secondWire), "HTTP/1.1 422 "))) ||
				(mode == "late-second" && secondErr == nil) {
				t.Fatalf("invalid postwrite second completed: %v, %q", secondErr, secondWire)
			}
		}
	}
	switch mode {
	case "valid":
		if routeErr != nil || !strings.HasPrefix(string(wire), "HTTP/1.1 200 ") ||
			!bytes.Contains(wire, []byte("event: message_stop\n")) ||
			!ingressAttempted || !prewriteAttempted || !completionAttempted || !sequence.target {
			t.Fatalf("full observed response not delivered: %v, %q", routeErr, wire)
		}
	case "invalid-auth", "expired-auth":
		if routeErr == nil || !strings.HasPrefix(string(wire), "HTTP/1.1 503 ") ||
			bytes.Contains(wire, []byte("event:")) ||
			!ingressAttempted || prewriteAttempted || completionAttempted {
			t.Fatalf("forged authorization reached SSE or prewrite: %v, %q", routeErr, wire)
		}
	case "write-failure", "invalid-proof", "expired-proof", "wrong-core-proof",
		"expired-before-write", "bare-receipt", "wrong-epoch-proof":
		if routeErr == nil || len(wire) != 0 || !ingressAttempted ||
			!prewriteAttempted || completionAttempted {
			t.Fatalf("failed prewrite proof or write reached SSE/completion: %v, %q", routeErr, wire)
		}
	case "stopped-before-write":
		if routeErr == nil || len(wire) != 0 || !ingressAttempted ||
			!prewriteAttempted || completionAttempted {
			t.Fatalf("stopped broker socket reached SSE: %v, %q", routeErr, wire)
		}
	case "bad-ack":
		if routeErr == nil || !strings.HasPrefix(string(wire), "HTTP/1.1 200 ") ||
			!ingressAttempted || !prewriteAttempted || !completionAttempted {
			t.Fatalf("bad completion ack handling: %v, %q", routeErr, wire)
		}
	case "target-before-second", "missing-second", "wrong-peer-second", "late-second":
		if !ingressAttempted || !prewriteAttempted ||
			completionAttempted != (mode == "target-before-second") {
			t.Fatalf("postwrite completion attempt mismatch: %s", mode)
		}
	}
	if err := <-hDone; err != nil {
		t.Fatalf("H did not see one valid ingress/prewrite/completion: %v", err)
	}
	close(releaseH)
}

func TestObservedTargetNeedsSignedProviderAndFullWriteCompletion(t *testing.T) {
	runObservedTargetRoute(t, "valid")
}

func TestObservedForgedAuthorizationProducesNoSSE(t *testing.T) {
	runObservedTargetRoute(t, "invalid-auth")
}

func TestObservedExpiredAuthorizationProducesNoSSE(t *testing.T) {
	runObservedTargetRoute(t, "expired-auth")
}

func TestObservedFailedFullWriteCannotComplete(t *testing.T) {
	runObservedTargetRoute(t, "write-failure")
}

func TestObservedForgedPrewriteProofProducesNoSSE(t *testing.T) {
	runObservedTargetRoute(t, "invalid-proof")
}

func TestObservedExpiredPrewriteProofProducesNoSSE(t *testing.T) {
	runObservedTargetRoute(t, "expired-proof")
}

func TestObservedMismatchedPrewriteProofProducesNoSSE(t *testing.T) {
	runObservedTargetRoute(t, "wrong-core-proof")
}

func TestObservedProofExpiryAtFirstByteProducesNoSSE(t *testing.T) {
	runObservedTargetRoute(t, "expired-before-write")
}

func TestObservedBarePrewriteReceiptProducesNoSSE(t *testing.T) {
	runObservedTargetRoute(t, "bare-receipt")
}

func TestObservedWrongEpochProofProducesNoSSE(t *testing.T) {
	runObservedTargetRoute(t, "wrong-epoch-proof")
}

func TestObservedStoppedBrokerCannotStartSSE(t *testing.T) {
	runObservedTargetRoute(t, "stopped-before-write")
}

func TestObservedBadCompletionAckCannotQualify(t *testing.T) {
	runObservedTargetRoute(t, "bad-ack")
}

func TestObservedTargetBeforeSecondCompletesAfterSamePeerSecond(t *testing.T) {
	runObservedTargetRoute(t, "target-before-second")
}

func TestObservedTargetWithoutSecondCannotComplete(t *testing.T) {
	runObservedTargetRoute(t, "missing-second")
}

func TestObservedWrongPeerSecondCannotComplete(t *testing.T) {
	runObservedTargetRoute(t, "wrong-peer-second")
}

func TestObservedLateSecondCannotComplete(t *testing.T) {
	runObservedTargetRoute(t, "late-second")
}

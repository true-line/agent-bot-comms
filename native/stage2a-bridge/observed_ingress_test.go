package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestObservedIngressUsesSameBrokerAndSpentMachineAuthorization(t *testing.T) {
	data, err := os.ReadFile("testdata/local-test-golden-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		RawFD4Hex string `json:"raw_fd4_hex"`
		Selectors struct {
			Reservation string `json:"reservation_digest"`
		} `json:"selectors"`
		Ingress struct {
			Core observedIngressCore `json:"core"`
		} `json:"ingress"`
	}
	if json.Unmarshal(data, &vector) != nil {
		t.Fatal("invalid shared ingress vector")
	}
	rawFD4, err := hex.DecodeString(vector.RawFD4Hex)
	if err != nil {
		t.Fatal(err)
	}
	key, err := observedSubkey(rawFD4, vector.Selectors.Reservation, observedIngressKeyContext)
	if err != nil {
		t.Fatal(err)
	}
	core := vector.Ingress.Core
	core.TargetReceivedAt = time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)
	coreBytes, err := canonicalJSONValue(core)
	if err != nil {
		t.Fatal(err)
	}
	wantMAC, err := observedOriginMAC(key, observedIngressOriginContext, core)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x88}, 32))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	purpose := observedAuthorizationPurpose
	payload := map[string]any{
		"schema":                "agent-bot-machine/stage2a-observed-body-local-test-ingress-authorization/v1",
		"kind":                  "observed-body-local-test-ingress-authorization",
		"selectors":             core.Selectors,
		"ingress_core_sha256":   digest(coreBytes),
		"provider_claim_sha256": digest([]byte("spent provider claim")),
		"issued_at":             now.Add(-time.Second).Format(time.RFC3339Nano),
		"expires_at":            now.Add(5 * time.Second).Format(time.RFC3339Nano),
	}
	payloadBytes, err := canonicalJSONValue(payload)
	if err != nil {
		t.Fatal(err)
	}
	envelopeBytes, err := canonicalJSONValue(map[string]any{
		"schema_version": 1, "purpose": purpose,
		"issuer_public_key_base64url": base64.RawURLEncoding.EncodeToString(publicKey),
		"payload_sha256":              digest(payloadBytes),
		"payload_base64url":           base64.RawURLEncoding.EncodeToString(payloadBytes),
		"signature_base64url": base64.RawURLEncoding.EncodeToString(
			ed25519.Sign(privateKey, append([]byte(purpose+"\x00"), payloadBytes...))),
	})
	if err != nil {
		t.Fatal(err)
	}
	authReply := observedAuthorizationReply{
		Envelope:    base64.RawURLEncoding.EncodeToString(envelopeBytes),
		EnvelopeSHA: digest(envelopeBytes),
	}
	provider := observedProviderResponse{Mode: "observed-body-local-test/v1",
		Model: "fixture-model", ObservedBodySHA256: core.ObservedBodySHA256,
		ResponseText: "fixture response", ResponseSHA256: digest([]byte("fixture response")),
		Invocation: 1}
	requestBytes, err := canonicalJSONValue(map[string]any{
		"mode": provider.Mode, "model": provider.Model,
		"observed_body_sha256": provider.ObservedBodySHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	responseBytes, err := canonicalJSONValue(provider)
	if err != nil {
		t.Fatal(err)
	}
	fixtureBytes, err := canonicalJSONValue(map[string]any{
		"schema": "stage2a-observed-body-local-test-fixture/v1",
		"model":  provider.Model, "response_text": provider.ResponseText,
	})
	if err != nil {
		t.Fatal(err)
	}
	reply := observedIngressResult{observedAuthorizationReply: authReply,
		IngressCoreSHA256: digest(coreBytes), Provider: provider,
		ProviderRequestBodySHA256:  digest(requestBytes),
		ProviderResponseBodySHA256: digest(responseBytes)}
	authority := observedAuthority{FD3: observedFD3{Selectors: core.Selectors,
		Expires: now.Add(10 * time.Second), LocalTest: observedLocalTest{
			Model: provider.Model, FixtureConfigSHA256: digest(fixtureBytes),
		}}, ResponseTextSHA256: provider.ResponseSHA256}
	copy(authority.Pin[:], publicKey)
	dir, err := os.MkdirTemp("/tmp", "observed-ingress-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "broker.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(path, 0660); err != nil {
		t.Fatal(err)
	}
	parent, _ := observe(dir, os.ModeDir)
	socket, _ := observe(path, os.ModeSocket)
	e := endpoint{Path: path, Parent: parent, Socket: socket}
	serverDone := make(chan error, 1)
	releaseServer := make(chan struct{})
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		reader := bufio.NewScanner(conn)
		if !reader.Scan() {
			serverDone <- invalid
			return
		}
		var request struct {
			ID      string                 `json:"id"`
			Op      string                 `json:"op"`
			Payload observedIngressPayload `json:"payload"`
		}
		if decode(reader.Bytes(), &request) != nil || request.ID != "ingress" ||
			request.Op != observedIngressOp || request.Payload.Core != core ||
			request.Payload.IngressOriginMAC != wantMAC {
			serverDone <- invalid
			return
		}
		if err := json.NewEncoder(conn).Encode(map[string]any{
			"id": request.ID, "ok": true, "result": reply,
		}); err != nil {
			serverDone <- err
			return
		}
		serverDone <- nil
		<-releaseServer
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b, err := openBroker(ctx, assignment{Broker: e, HQUID: parent.UID},
		func(*net.UnixConn) (uint32, error) { return parent.UID, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer b.conn.Close()
	attempted := false
	authorized, err := b.authorizeObserved(ctx, core, key, authority,
		e.current, &attempted)
	if err != nil || !attempted || authorized.AuthorizationEnvelopeSHA256 != reply.EnvelopeSHA ||
		authorized.IngressCoreSHA256 != digest(coreBytes) {
		t.Fatalf("signed B origin ingress refused: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("H saw altered ingress core or MAC: %v", err)
	}
	close(releaseServer)
	for _, value := range key {
		if value != 0 {
			t.Fatal("ingress subkey retained after attempt")
		}
	}
	if _, err := b.authorizeObserved(ctx, core, key, authority,
		e.current, &attempted); err == nil {
		t.Fatal("second provider ingress accepted")
	}
	if strings.Contains(string(coreBytes), "spent provider claim") {
		t.Fatal("claim content leaked into B ingress")
	}
}

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCooperativePeerWarrantJoinsAcceptedCLIToSignedMember(t *testing.T) {
	a, pair, pin, base := policyFixture(t)
	policy, err := verifyCooperativePolicy(pair, a, pin,
		fixtureEndpoint(t, a.BrokerRecord, true), fixtureEndpoint(t, a.RelayRecord, false), base)
	if err != nil {
		t.Fatal(err)
	}
	observationRaw, err := os.ReadFile("testdata/v3-cooperative-observation.jcs")
	if err != nil {
		t.Fatal(err)
	}
	observation, err := verifyCooperativeObservation(base64.RawURLEncoding.EncodeToString(
		bytes.TrimSpace(observationRaw)), policy, base.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	relay := fixtureEndpoint(t, a.RelayRecord, true)
	child := observation.Children[0]
	peer := peerProcessSnapshot{Peer: peerProcessIdentity{UID: child.UID, PID: 8101, PIDVersion: 3},
		StartSeconds: 111, StartMicros: 4, ParentPID: int(child.PID), ParentUID: child.UID,
		ParentStartSeconds: uint64(child.StartSeconds), ParentStartMicros: uint64(child.StartMicros)}
	if selected, err := cooperativePeerMember(policy, observation, peer); err != nil || selected != 0 {
		t.Fatalf("signed parent did not select first member: %d %v", selected, err)
	}
	ready := cooperativeReadyState{
		SHA: "sha256:" + strings.Repeat("7", 64), Expires: base.Add(10 * time.Second),
		Observed: cooperativeObservedB{SHA: "sha256:" + strings.Repeat("8", 64),
			Bridge: map[string]any{"pid": jcsInteger(4002), "uid": jcsInteger(int64(a.BridgeUID)),
				"gid": jcsInteger(int64(a.BridgeUID)), "start_seconds": jcsInteger(100),
				"start_micros": jcsInteger(42)}},
		Lease: cooperativeBLive{SHA: "sha256:" + strings.Repeat("9", 64),
			Sequence: 2, Expires: base.Add(8 * time.Second)}, BirthNS: 12345,
	}
	memberLease := cooperativeMemberLease{SHA: "sha256:" + strings.Repeat("6", 64),
		Sequence: 1, Expires: base.Add(7 * time.Second)}
	nonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, 32))
	payload := map[string]any{
		"contract": "machine/v3", "kind": "soul-cooperative-relay-peer",
		"schema_version": jcsInteger(3), "profile_in_force": "managed-cooperative",
		"host_id": a.HostID, "installation_id": a.Installation,
		"start_id": a.Start, "launch_id": a.Launch, "hq_epoch": a.Epoch,
		"reservation_sha256":                 a.ReservationSHA,
		"assignment_envelope_sha256":         policy.FD3.Selectors.AssignmentDigest,
		"member_b_authority_envelope_sha256": policy.FD3.Selectors.AuthorityDigest,
		"bridge_observed_sha256":             ready.Observed.SHA, "ready_sha256": ready.SHA,
		"b_lease_sha256": ready.Lease.SHA, "b_lease_sequence": jcsInteger(ready.Lease.Sequence),
		"member_lease_sha256":       memberLease.SHA,
		"member_lease_sequence":     jcsInteger(memberLease.Sequence),
		"member_id":                 policy.Members[0].ID,
		"member_launch_id":          policy.Members[0].Launch,
		"member_selector":           policy.Members[0].Selector,
		"bridge_process":            ready.Observed.Bridge,
		"adapter_process":           cooperativeAdapterValue(child),
		"relay_socket":              relayClaimValue(relay),
		"relay_socket_birthtime_ns": strconv.FormatInt(ready.BirthNS, 10),
		"cli_path":                  policy.Members[0].CLIPath,
		"cli_sha256":                policy.Members[0].CLIDigest,
		"peer":                      cooperativePeerValue(peer),
		"challenge_nonce_base64url": nonce,
		"issued_at":                 base.UTC().Format(time.RFC3339Nano),
		"expires_at":                base.Add(4 * time.Second).UTC().Format(time.RFC3339Nano),
	}
	canonical, err := canonicalBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x75}, 32))
	public := private.Public().(ed25519.PublicKey)
	copy(policy.Pin[:], public)
	envelope := map[string]any{
		"schema_version": jcsInteger(3), "purpose": cooperativeRelayPeerPurpose,
		"issuer_public_key_base64url": base64.RawURLEncoding.EncodeToString(public),
		"payload_sha256":              digest(canonical),
		"payload_base64url":           base64.RawURLEncoding.EncodeToString(canonical),
		"signature_base64url": base64.RawURLEncoding.EncodeToString(ed25519.Sign(private,
			append([]byte(cooperativeRelayPeerPurpose+"\x00"), canonical...))),
	}
	raw, err := canonicalBytes(envelope)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	now := base.Add(2 * time.Second)
	warrant, err := verifyCooperativeRelayPeer(encoded, a, policy, observation,
		ready, memberLease, 0, peer, nonce, relay, now)
	if err != nil || warrant.SHA != digest(raw) {
		t.Fatalf("signed peer warrant refused: %+v %v", warrant, err)
	}
	changed := peer
	changed.ParentStartMicros++
	if _, err := verifyCooperativeRelayPeer(encoded, a, policy, observation,
		ready, memberLease, 0, changed, nonce, relay, now); err == nil {
		t.Fatal("replaced ACP parent accepted")
	}
	changedLease := memberLease
	changedLease.Sequence++
	if _, err := verifyCooperativeRelayPeer(encoded, a, policy, observation,
		ready, changedLease, 0, peer, nonce, relay, now); err == nil {
		t.Fatal("changed member lease accepted")
	}
	if _, err := verifyCooperativeRelayPeer(encoded, a, policy, observation,
		ready, memberLease, 1, peer, nonce, relay, now); err == nil {
		t.Fatal("wrong member accepted")
	}
	if _, err := verifyCooperativeRelayPeer(encoded, a, policy, observation,
		ready, memberLease, 0, peer, nonce, relay, base.Add(4*time.Second)); err == nil {
		t.Fatal("expired peer warrant accepted")
	}
}

func TestCooperativeIngressRefusesTextOutsideSignedMemberPolicy(t *testing.T) {
	a, pair, pin, base := policyFixture(t)
	policy, err := verifyCooperativePolicy(pair, a, pin,
		fixtureEndpoint(t, a.BrokerRecord, true), fixtureEndpoint(t, a.RelayRecord, false), base)
	if err != nil {
		t.Fatal(err)
	}
	member := policy.Members[0]
	zero := 0
	result := qualificationResult{Model: member.Policy.Model,
		Text: member.ResponseText, Stop: "end_turn"}
	result.Usage.Input, result.Usage.Output = &zero, &zero
	if !cooperativeResultMatchesMember(&result, member) {
		t.Fatal("signed member response was refused")
	}
	result.Text = "different local provider response"
	if cooperativeResultMatchesMember(&result, member) {
		t.Fatal("wrong H provider text accepted against A-signed qualification")
	}
}

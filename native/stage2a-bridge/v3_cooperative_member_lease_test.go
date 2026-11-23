package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCooperativeMemberLeaseBindsFreshChallengeAndObservedChild(t *testing.T) {
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
	child := observation.Children[0]
	ready := "sha256:" + strings.Repeat("7", 64)
	nonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, 32))
	payload := map[string]any{
		"contract": "machine/v3", "kind": "soul-cooperative-member-live-lease",
		"schema_version": jcsInteger(3), "profile_in_force": "managed-cooperative",
		"reservation_sha256":         policy.FD3.Selectors.Reservation,
		"assignment_envelope_sha256": policy.FD3.Selectors.AssignmentDigest,
		"ready_envelope_sha256":      ready,
		"member_id":                  policy.Members[0].ID,
		"member_launch_id":           policy.Members[0].Launch,
		"member_selector":            policy.Members[0].Selector,
		"grant_sha256":               child.GrantDigest,
		"launcher_process": map[string]any{
			"pid": jcsInteger(child.LauncherPID), "uid": jcsInteger(int64(child.LauncherUID)),
			"gid":           jcsInteger(int64(child.LauncherGID)),
			"start_seconds": jcsInteger(child.LauncherStartSeconds),
			"start_micros":  jcsInteger(child.LauncherStartMicros),
		},
		"child_process": map[string]any{
			"pid": jcsInteger(child.PID), "uid": jcsInteger(int64(child.UID)),
			"gid": jcsInteger(int64(child.GID)), "parent_pid": jcsInteger(child.ParentPID),
			"process_group_id":  jcsInteger(child.ProcessGroup),
			"start_seconds":     jcsInteger(child.StartSeconds),
			"start_micros":      jcsInteger(child.StartMicros),
			"executable_sha256": child.CommandDigest,
		},
		"challenge_nonce_base64url": nonce, "sequence": jcsInteger(1),
		"issued_at":  base.UTC().Format(time.RFC3339Nano),
		"expires_at": base.Add(4 * time.Second).UTC().Format(time.RFC3339Nano),
	}
	canonical, err := canonicalBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x74}, 32))
	public := private.Public().(ed25519.PublicKey)
	copy(policy.Pin[:], public)
	envelope := map[string]any{
		"schema_version": jcsInteger(3), "purpose": cooperativeMemberLivePurpose,
		"issuer_public_key_base64url": base64.RawURLEncoding.EncodeToString(public),
		"payload_sha256":              digest(canonical),
		"payload_base64url":           base64.RawURLEncoding.EncodeToString(canonical),
		"signature_base64url": base64.RawURLEncoding.EncodeToString(ed25519.Sign(private,
			append([]byte(cooperativeMemberLivePurpose+"\x00"), canonical...))),
	}
	raw, err := canonicalBytes(envelope)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	now := base.Add(2 * time.Second)
	lease, err := verifyCooperativeMemberLease(encoded, policy, observation, 0, ready,
		nonce, 0, base.Add(5*time.Second), now)
	if err != nil || lease.Sequence != 1 || lease.SHA != digest(raw) {
		t.Fatalf("signed live member lease refused: %+v %v", lease, err)
	}
	if _, err := verifyCooperativeMemberLease(encoded, policy, observation, 0, ready,
		nonce, 1, base.Add(5*time.Second), now); err == nil {
		t.Fatal("replayed member lease accepted")
	}
	if _, err := verifyCooperativeMemberLease(encoded, policy, observation, 0, ready,
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x62}, 32)), 0,
		base.Add(5*time.Second), now); err == nil {
		t.Fatal("wrong challenge accepted")
	}
	changed := observation
	changed.Children[0].PID++
	if _, err := verifyCooperativeMemberLease(encoded, policy, changed, 0, ready,
		nonce, 0, base.Add(5*time.Second), now); err == nil {
		t.Fatal("changed observed ACP child accepted")
	}
	if _, err := verifyCooperativeMemberLease(encoded, policy, observation, 1, ready,
		nonce, 0, base.Add(5*time.Second), now); err == nil {
		t.Fatal("wrong member accepted")
	}
}

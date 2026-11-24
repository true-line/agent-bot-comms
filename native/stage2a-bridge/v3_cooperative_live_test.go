package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func signedBLiveFixture(t *testing.T, a cooperativeBridgeAuthority, policy v3Authority,
	observed cooperativeObservedB, readySHA, nonce string, relay endpoint,
	issued, expires time.Time, sequence int64) (string, []byte) {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x73}, 32))
	public := private.Public().(ed25519.PublicKey)
	payload := map[string]any{
		"contract": "machine/v3", "kind": "soul-cooperative-b-live-lease",
		"schema_version": jcsInteger(3), "profile_in_force": "managed-cooperative",
		"host_id": a.HostID, "installation_id": a.Installation, "start_id": a.Start,
		"launch_id": a.Launch, "plan_id": a.Plan, "plan_digest": a.PlanDigest,
		"hq_epoch": a.Epoch, "reservation_sha256": a.ReservationSHA,
		"bridge_assignment_sha256":           a.AssignmentSHA,
		"assignment_envelope_sha256":         policy.FD3.Selectors.AssignmentDigest,
		"member_b_authority_envelope_sha256": policy.FD3.Selectors.AuthorityDigest,
		"bridge_observed_sha256":             observed.SHA, "ready_sha256": readySHA,
		"bridge_process": observed.Bridge, "relay_socket": relayClaimValue(relay),
		"challenge_nonce_base64url": nonce, "sequence": jcsInteger(sequence),
		"issued_at":  issued.UTC().Format(time.RFC3339Nano),
		"expires_at": expires.UTC().Format(time.RFC3339Nano),
	}
	canonical, err := canonicalBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	envelope := map[string]any{
		"schema_version": jcsInteger(3), "purpose": cooperativeBLivePurpose,
		"issuer_public_key_base64url": base64.RawURLEncoding.EncodeToString(public),
		"payload_sha256":              digest(canonical),
		"payload_base64url":           base64.RawURLEncoding.EncodeToString(canonical),
		"signature_base64url": base64.RawURLEncoding.EncodeToString(ed25519.Sign(private,
			append([]byte(cooperativeBLivePurpose+"\x00"), canonical...))),
	}
	raw, err := canonicalBytes(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), public
}

func TestCooperativeBLiveShortSignedJoin(t *testing.T) {
	a, pair, pin, base := policyFixture(t)
	policy, err := verifyCooperativePolicy(pair, a, pin,
		fixtureEndpoint(t, a.BrokerRecord, true), fixtureEndpoint(t, a.RelayRecord, false), base)
	if err != nil {
		t.Fatal(err)
	}
	relay := fixtureEndpoint(t, a.RelayRecord, true)
	observed := cooperativeObservedB{
		SHA: "sha256:" + strings.Repeat("8", 64), Expires: a.Expires,
		Bridge: map[string]any{"pid": jcsInteger(4002), "uid": jcsInteger(int64(a.BridgeUID)),
			"gid": jcsInteger(int64(a.BridgeUID)), "start_seconds": jcsInteger(100),
			"start_micros": jcsInteger(42)},
		Launcher: map[string]any{"pid": jcsInteger(4001), "uid": jcsInteger(int64(a.BridgeUID)),
			"gid": jcsInteger(int64(a.BridgeUID)), "start_seconds": jcsInteger(99),
			"start_micros": jcsInteger(41)},
	}
	readySHA := "sha256:" + strings.Repeat("7", 64)
	nonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, 32))
	encoded, public := signedBLiveFixture(t, a, policy, observed, readySHA, nonce,
		relay, base, base.Add(4*time.Second), 1)
	copy(policy.Pin[:], public)
	current := func(endpoint) bool { return true }
	self := func(bridge, launcher map[string]any) bool { return true }
	lease, err := verifyCooperativeBLive(encoded, a, policy, observed, readySHA, nonce, 0,
		a.Expires, relay, base.Add(time.Second), current, self)
	if err != nil || lease.Sequence != 1 || !validDigest(lease.SHA) ||
		!lease.Expires.Equal(base.Add(4*time.Second)) {
		t.Fatalf("signed short B lease refused: %+v %v", lease, err)
	}
	for name, check := range map[string]func() error{
		"wrong Ready": func() error {
			_, err := verifyCooperativeBLive(encoded, a, policy, observed,
				"sha256:"+strings.Repeat("0", 64), nonce, 0,
				a.Expires, relay, base.Add(time.Second), current, self)
			return err
		},
		"wrong sequence": func() error {
			_, err := verifyCooperativeBLive(encoded, a, policy, observed, readySHA, nonce,
				1, a.Expires, relay, base.Add(time.Second), current, self)
			return err
		},
		"expired": func() error {
			_, err := verifyCooperativeBLive(encoded, a, policy, observed, readySHA, nonce,
				0, a.Expires, relay, lease.Expires, current, self)
			return err
		},
		"changed relay": func() error {
			changed := relay
			changed.Socket.Inode++
			_, err := verifyCooperativeBLive(encoded, a, policy, observed, readySHA, nonce,
				0, a.Expires, changed, base.Add(time.Second), current, self)
			return err
		},
		"stale B": func() error {
			_, err := verifyCooperativeBLive(encoded, a, policy, observed, readySHA, nonce,
				0, a.Expires, relay, base.Add(time.Second), current,
				func(map[string]any, map[string]any) bool { return false })
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := check(); err == nil {
				t.Fatal("invalid B lease accepted")
			}
		})
	}
}

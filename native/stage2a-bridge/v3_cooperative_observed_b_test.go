package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"
)

func signedObservedBFixture(t *testing.T, a cooperativeBridgeAuthority, relay endpoint,
	bindReceipt string, birth int64, now time.Time) (string, []byte) {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, 32))
	public := private.Public().(ed25519.PublicKey)
	role := map[string]any{"pid": jcsInteger(4001), "uid": jcsInteger(int64(a.BridgeUID)),
		"gid": jcsInteger(int64(a.BridgeUID)), "start_seconds": jcsInteger(100),
		"start_micros": jcsInteger(42)}
	bridge := map[string]any{"pid": jcsInteger(4002), "uid": jcsInteger(int64(a.BridgeUID)),
		"gid": jcsInteger(int64(a.BridgeUID)), "start_seconds": jcsInteger(101),
		"start_micros": jcsInteger(43)}
	payload := map[string]any{
		"contract": "machine/v3", "kind": "soul-cooperative-b-observed",
		"schema_version": jcsInteger(3), "reservation_sha256": a.ReservationSHA,
		"bridge_assignment_sha256": a.AssignmentSHA, "bind_receipt_sha256": bindReceipt,
		"installation_id": a.Installation, "start_id": a.Start, "launch_id": a.Launch,
		"plan_id": a.Plan, "plan_digest": a.PlanDigest, "hq_epoch": a.Epoch,
		"grant_nonce": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, 32)),
		"launcher":    role, "bridge": bridge,
		"relay_socket": map[string]any{"path": relay.Path, "socket": map[string]any{
			"uid": jcsInteger(int64(relay.Socket.UID)), "gid": jcsInteger(int64(relay.Socket.GID)),
			"device": strconv.FormatUint(relay.Socket.Device, 10), "inode": strconv.FormatUint(relay.Socket.Inode, 10),
			"mode": jcsInteger(int64(relay.Socket.Mode))}},
		"relay_socket_birthtime_ns": strconv.FormatInt(birth, 10),
		"observed_at":               now.UTC().Format(time.RFC3339Nano),
		"expires_at":                a.Expires.UTC().Format(time.RFC3339Nano),
	}
	canonical, err := canonicalBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	envelope := map[string]any{
		"schema_version": jcsInteger(3), "purpose": cooperativeBObservedPurpose,
		"issuer_public_key_base64url": base64.RawURLEncoding.EncodeToString(public),
		"payload_sha256":              digest(canonical),
		"payload_base64url":           base64.RawURLEncoding.EncodeToString(canonical),
		"signature_base64url": base64.RawURLEncoding.EncodeToString(ed25519.Sign(private,
			append([]byte(cooperativeBObservedPurpose+"\x00"), canonical...))),
	}
	raw, err := canonicalBytes(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), public
}

func TestCooperativeBObservedJoinsFD5RelayAndSelf(t *testing.T) {
	a, _, _, base := policyFixture(t)
	relay := fixtureEndpoint(t, a.RelayRecord, true)
	receipt := "sha256:" + strings.Repeat("f", 64)
	birth := int64(123456789)
	encoded, pin := signedObservedBFixture(t, a, relay, receipt, birth, base)
	self := func(bridge, launcher map[string]any) bool {
		return integer(bridge, "pid") == 4002 && integer(launcher, "pid") == 4001
	}
	observed, err := verifyCooperativeBObserved(encoded, a, pin, receipt, relay, birth,
		base.Add(time.Second), self)
	if err != nil || !validDigest(observed.SHA) || !base.Before(observed.Expires) {
		t.Fatalf("signed B observation refused: %v", err)
	}
	for name, check := range map[string]func() (cooperativeObservedB, error){
		"wrong FD5 receipt": func() (cooperativeObservedB, error) {
			return verifyCooperativeBObserved(encoded, a, pin, "sha256:"+strings.Repeat("0", 64),
				relay, birth, base.Add(time.Second), self)
		},
		"wrong socket birthtime": func() (cooperativeObservedB, error) {
			return verifyCooperativeBObserved(encoded, a, pin, receipt, relay, birth+1,
				base.Add(time.Second), self)
		},
		"wrong Machine pin": func() (cooperativeObservedB, error) {
			return verifyCooperativeBObserved(encoded, a, append([]byte(nil), pin[:31]...), receipt,
				relay, birth, base.Add(time.Second), self)
		},
		"changed self process": func() (cooperativeObservedB, error) {
			return verifyCooperativeBObserved(encoded, a, pin, receipt, relay, birth,
				base.Add(time.Second), func(map[string]any, map[string]any) bool { return false })
		},
		"expired": func() (cooperativeObservedB, error) {
			return verifyCooperativeBObserved(encoded, a, pin, receipt, relay, birth, observed.Expires, self)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := check(); err == nil {
				t.Fatal("changed B observation accepted")
			}
		})
	}
}

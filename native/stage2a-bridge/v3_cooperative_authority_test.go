package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

type cooperativePairFixture struct {
	Reservation   string `json:"reservation_envelope_jcs"`
	Bridge        string `json:"bridge_envelope_jcs"`
	PublicKey     string `json:"issuer_public_key_base64url"`
	ContractsHead string `json:"contracts_head"`
}

func cooperativeFixture(t *testing.T) ([]byte, []byte, []byte, time.Time) {
	t.Helper()
	data, err := os.ReadFile("testdata/v3-cooperative-signed-pair.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture cooperativePairFixture
	if decode(data, &fixture) != nil ||
		fixture.ContractsHead != "b223e72c5e923d1833a2879c30e1670201bed7f8" {
		t.Fatal("invalid pinned Contracts fixture")
	}
	pin, err := base64.RawURLEncoding.DecodeString(fixture.PublicKey)
	if err != nil || len(pin) != ed25519.PublicKeySize {
		t.Fatal("invalid Contracts A key")
	}
	reservationEnvelope := []byte(fixture.Reservation)
	reservation, err := signedCooperativePayload(reservationEnvelope, pin, cooperativeReservationPurpose)
	if err != nil {
		t.Fatal("invalid Contracts reservation")
	}
	issued, err := time.Parse(time.RFC3339Nano, field(reservation, "issued_at"))
	if err != nil {
		t.Fatal(err)
	}
	return reservationEnvelope, []byte(fixture.Bridge), pin, issued.Add(time.Second)
}

func TestCooperativeFD3ClosedSignedFrame(t *testing.T) {
	reservation, bridge, pin, now := cooperativeFixture(t)
	frame := cooperativeFD3{Version: cooperativeStartVersion, MachinePinPath: v3PinPath,
		ReservationEnvelope: base64.RawURLEncoding.EncodeToString(reservation),
		BridgeEnvelope:      base64.RawURLEncoding.EncodeToString(bridge)}
	raw, err := json.Marshal(frame)
	if err != nil || len(raw) > cooperativeFD3MaxBytes {
		t.Fatalf("published pair does not fit 32 KiB FD3: %d %v", len(raw), err)
	}
	verified, err := verifyCooperativeFD3(raw, pin, now)
	if err != nil || verified.BridgeUID == 0 {
		t.Fatalf("signed cooperative FD3 refused: %+v %v", verified, err)
	}
	atLimit := append(append([]byte(nil), raw...),
		bytes.Repeat([]byte(" "), cooperativeFD3MaxBytes-len(raw))...)
	if _, err := verifyCooperativeFD3(atLimit, pin, now); err != nil {
		t.Fatal("valid cooperative FD3 refused at its exact byte cap")
	}
	if _, err := verifyCooperativeFD3(append(atLimit, ' '), pin, now); err == nil {
		t.Fatal("cooperative FD3 over its byte cap accepted")
	}
	for _, change := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"wrong version", func(m map[string]any) { m["version"] = v3Version }},
		{"wrong pin path", func(m map[string]any) { m["machine_pin_path"] = "/tmp/other.pub" }},
		{"extra field", func(m map[string]any) { m["member_policy"] = "unreviewed" }},
		{"padded envelope", func(m map[string]any) {
			m["bridge_assignment_envelope_base64url"] = m["bridge_assignment_envelope_base64url"].(string) + "="
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			var copy map[string]any
			if json.Unmarshal(raw, &copy) != nil {
				t.Fatal("invalid test frame")
			}
			change.edit(copy)
			altered, _ := json.Marshal(copy)
			if _, err := verifyCooperativeFD3(altered, pin, now); err == nil {
				t.Fatal("altered cooperative FD3 accepted")
			}
		})
	}
}

func TestCooperativeSignedBridgePair(t *testing.T) {
	reservation, bridge, pin, now := cooperativeFixture(t)
	authority, err := verifyCooperativeBridgePair(reservation, bridge, pin, now)
	if err != nil || authority.BridgeUID == authority.RunnerUID ||
		authority.BrokerPath == authority.RelayPath ||
		authority.ReservationSHA != digest(reservation) ||
		authority.AssignmentSHA != digest(bridge) {
		t.Fatalf("published A-signed cooperative pair refused or lost binding: %+v %v", authority, err)
	}
	if _, err := verifyCooperativeBridgePair(reservation, bridge, pin, authority.Expires); err == nil {
		t.Fatal("expired cooperative pair accepted")
	}
	wrongPin := append([]byte(nil), pin...)
	wrongPin[0] ^= 1
	if _, err := verifyCooperativeBridgePair(reservation, bridge, wrongPin, now); err == nil {
		t.Fatal("wrong installed A pin accepted")
	}
	tampered := append([]byte(nil), bridge...)
	tampered[len(tampered)/2] ^= 1
	if _, err := verifyCooperativeBridgePair(reservation, tampered, pin, now); err == nil {
		t.Fatal("tampered cooperative signature accepted")
	}
	if _, err := verifyCooperativeBridgePair(bridge, reservation, pin, now); err == nil {
		t.Fatal("cross-purpose cooperative envelopes accepted")
	}
}

func cooperativeTestPayload(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	envelope, err := canonicalSignedJSONBounded(raw, 2<<20)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := unpadded(field(envelope, "payload_base64url"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	result, err := canonicalSignedJSONBounded(payload, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func signCooperativeTestPayload(t *testing.T, payload map[string]any,
	purpose string, key ed25519.PrivateKey) []byte {
	t.Helper()
	canonical, err := canonicalBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	issuer := key.Public().(ed25519.PublicKey)
	envelope := map[string]any{
		"schema_version":              json.Number("3"),
		"purpose":                     purpose,
		"issuer_public_key_base64url": base64.RawURLEncoding.EncodeToString(issuer),
		"payload_sha256":              digest(canonical),
		"payload_base64url":           base64.RawURLEncoding.EncodeToString(canonical),
		"signature_base64url": base64.RawURLEncoding.EncodeToString(
			ed25519.Sign(key, append([]byte(purpose+"\x00"), canonical...))),
	}
	raw, err := canonicalBytes(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCooperativeSignedPairRefusesCrossRecordSplices(t *testing.T) {
	reservationRaw, bridgeRaw, _, now := cooperativeFixture(t)
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("b", 32)))
	pin := key.Public().(ed25519.PublicKey)
	for _, tc := range []struct {
		name string
		edit func(map[string]any, map[string]any)
	}{
		{"reservation digest", func(_, bridge map[string]any) {
			bridge["reservation_sha256"] = "sha256:" + strings.Repeat("0", 64)
		}},
		{"bridge launch digest", func(_, bridge map[string]any) {
			bridge["bridge_launch_sha256"] = "sha256:" + strings.Repeat("0", 64)
		}},
		{"different member endpoint", func(_, bridge map[string]any) {
			endpoints, _ := object(bridge["endpoints"])
			member, _ := object(endpoints["member"])
			member["parent_inode"] = "2009"
		}},
		{"wrong broker peer", func(_, bridge map[string]any) {
			endpoints, _ := object(bridge["endpoints"])
			broker, _ := object(endpoints["broker"])
			broker["expected_peer_uid"] = json.Number("331")
		}},
		{"extra bridge argument", func(_, bridge map[string]any) {
			b, _ := object(bridge["bridge"])
			args, _ := array(b["argv"])
			b["argv"] = append(args, "--unreviewed")
		}},
		{"direct transport", func(reservation, _ map[string]any) {
			reservation["adapter_transport"] = "direct-comms"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reservation := cooperativeTestPayload(t, reservationRaw)
			bridge := cooperativeTestPayload(t, bridgeRaw)
			tc.edit(reservation, bridge)
			signedReservation := signCooperativeTestPayload(t, reservation, cooperativeReservationPurpose, key)
			if tc.name != "reservation digest" {
				bridge["reservation_sha256"] = digest(signedReservation)
			}
			signedBridge := signCooperativeTestPayload(t, bridge, cooperativeBridgePurpose, key)
			if _, err := verifyCooperativeBridgePair(signedReservation, signedBridge, pin, now); err == nil {
				t.Fatal("A-signed cross-record mismatch accepted")
			}
		})
	}
}

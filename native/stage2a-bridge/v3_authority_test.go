package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func v3Fixture(t *testing.T) ([]byte, []byte, time.Time) {
	t.Helper()
	raw, err := os.ReadFile("testdata/v3-fd3.json")
	if err != nil {
		t.Fatal(err)
	}
	var f v3FD3
	if decode(raw, &f) != nil {
		t.Fatal("invalid test fixture")
	}
	bytes, err := base64.RawURLEncoding.DecodeString(f.AssignmentEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := canonicalSignedJSON(bytes)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := base64.RawURLEncoding.DecodeString(field(envelope, "issuer_public_key_base64url"))
	if err != nil {
		t.Fatal(err)
	}
	return raw, pin, f.Expires.Add(-time.Second)
}

func TestV3SignedFD3Joins(t *testing.T) {
	raw, pin, now := v3Fixture(t)
	verified, err := verifyV3FD3(raw, pin, now)
	if err != nil {
		t.Fatalf("signed two-member fixture refused: %v", err)
	}
	if verified.Members[0].ID == verified.Members[1].ID ||
		verified.Members[0].Selector == verified.Members[1].Selector ||
		verified.Members[0].Policy.RequestDigest == "" {
		t.Fatal("lost signed member policy")
	}
	if _, err := verifyV3FD3(raw, pin, verified.FD3.Expires); err == nil {
		t.Fatal("expired FD3 accepted")
	}
	other := append([]byte(nil), pin...)
	other[0] ^= 1
	if _, err := verifyV3FD3(raw, other, now); err == nil {
		t.Fatal("wrong installed A key accepted")
	}
}

func TestV3BindProofExactNULVector(t *testing.T) {
	raw, pin, now := v3Fixture(t)
	verified, err := verifyV3FD3(raw, pin, now)
	if err != nil {
		t.Fatal(err)
	}
	key := []byte(strings.Repeat("k", 32))
	proof, err := v3BindProof(key, strings.Repeat("f", 64), verified.FD3)
	if err != nil || proof != "ecd12f6645d5af8e2496fc9713be73aa42f4570f17c36bb4653ccb44f4d9f8ac" {
		t.Fatalf("wrong v3 proof vector: %s %v", proof, err)
	}
	if _, err := v3BindProof(key, "short", verified.FD3); err == nil {
		t.Fatal("short nonce accepted")
	}
}

func TestV3SignedFD3RefusesTamper(t *testing.T) {
	raw, pin, now := v3Fixture(t)
	var f map[string]any
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("invalid fixture")
	}
	for _, change := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"wrong pin path", func(m map[string]any) { m["machine_pin_path"] = "/tmp/other.pub" }},
		{"wrong broker inode", func(m map[string]any) { m["broker"].(map[string]any)["socket"].(map[string]any)["inode"] = 0 }},
		{"wrong authority digest", func(m map[string]any) {
			m["selectors"].(map[string]any)["authority_envelope_sha256"] = "sha256:" + string(make([]byte, 64))
		}},
		{"wrong member selectors", func(m map[string]any) {
			m["selectors"].(map[string]any)["member_selectors_sha256"] = "sha256:" + string(make([]byte, 64))
		}},
		{"wrong bridge UID", func(m map[string]any) { m["bridge_uid"] = float64(300) }},
		{"extra top level", func(m map[string]any) { m["unreviewed_policy"] = true }},
	} {
		t.Run(change.name, func(t *testing.T) {
			var copy map[string]any
			if json.Unmarshal(raw, &copy) != nil {
				t.Fatal("fixture copy failed")
			}
			change.edit(copy)
			altered, _ := json.Marshal(copy)
			if _, err := verifyV3FD3(altered, pin, now); err == nil {
				t.Fatal("tampered FD3 accepted")
			}
		})
	}
}

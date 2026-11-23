package main

import (
	"encoding/base64"
	"os"
	"testing"
)

func TestV3SignedChildObservationJoins(t *testing.T) {
	raw, pin, now := v3Fixture(t)
	authority, err := verifyV3FD3(raw, pin, now)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := os.ReadFile("testdata/v3-observation.jcs")
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(envelope)
	observed, err := verifyV3Observation(encoded, authority, now)
	if err != nil {
		t.Fatalf("signed child observation refused: %v", err)
	}
	if observed.Children[0].MemberID != authority.Members[0].ID ||
		observed.Children[1].MemberID != authority.Members[1].ID ||
		observed.Children[0].PID == observed.Children[1].PID ||
		observed.MapDigest == "" || observed.EnvelopeDigest != digest(envelope) {
		t.Fatal("lost signed child/map join")
	}
	if _, err := verifyV3Observation(encoded, authority, observed.Expires); err == nil {
		t.Fatal("expired child observation accepted")
	}
	wrong := authority
	wrong.Members[0].CommandDigest = "sha256:" + "0" + wrong.Members[0].CommandDigest[8:]
	if _, err := verifyV3Observation(encoded, wrong, now); err == nil {
		t.Fatal("wrong pinned adapter digest accepted")
	}
	tampered := append([]byte(nil), envelope...)
	tampered[len(tampered)-3] ^= 1
	if _, err := verifyV3Observation(base64.RawURLEncoding.EncodeToString(tampered), authority, now); err == nil {
		t.Fatal("tampered A signature accepted")
	}
}

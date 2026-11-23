package main

import (
	"encoding/base64"
	"os"
	"testing"
	"time"
)

func TestV3BridgeArmMatchesContractsReceipt(t *testing.T) {
	raw, pin, fixtureNow := v3Fixture(t)
	authority, err := verifyV3FD3(raw, pin, fixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := os.ReadFile("testdata/v3-observation.jcs")
	if err != nil {
		t.Fatal(err)
	}
	observation, err := verifyV3Observation(
		base64.RawURLEncoding.EncodeToString(envelope), authority, fixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("testdata/v3-arm-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Members []struct {
			Arm    map[string]any `json:"bridge_arm"`
			Digest string         `json:"bridge_arm_receipt_sha256"`
		} `json:"members"`
	}
	if decode(data, &vector) != nil || len(vector.Members) != 2 {
		t.Fatal("invalid Contracts arm vector")
	}
	for i, expected := range vector.Members {
		armedAt, err := time.Parse(time.RFC3339Nano, field(expected.Arm, "armed_at"))
		if err != nil {
			t.Fatal(err)
		}
		_, receipt, err := makeV3BridgeArm(authority, authority.Members[i],
			observation.Children[i], observation, armedAt)
		if err != nil || receipt != expected.Digest {
			t.Fatalf("member %d arm differs from signed Ready vector: %v got=%s want=%s", i, err, receipt, expected.Digest)
		}
		if _, _, err := makeV3BridgeArm(authority, authority.Members[1-i],
			observation.Children[i], observation, armedAt); err == nil {
			t.Fatal("cross-member arm accepted")
		}
	}
}

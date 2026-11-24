package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCooperativeReadyJoinsSignedObservationAndArms(t *testing.T) {
	a, policy, pin, base := policyFixture(t)
	broker := fixtureEndpoint(t, a.BrokerRecord, true)
	relay := fixtureEndpoint(t, a.RelayRecord, false)
	authority, err := verifyCooperativePolicy(policy, a, pin, broker, relay, base)
	if err != nil {
		t.Fatal(err)
	}
	observationRaw, err := os.ReadFile("testdata/v3-cooperative-observation.jcs")
	if err != nil {
		t.Fatal(err)
	}
	observation, err := verifyCooperativeObservation(base64.RawURLEncoding.EncodeToString(
		bytes.TrimSpace(observationRaw)), authority, base.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	readyRaw, err := os.ReadFile("testdata/v3-cooperative-ready.jcs")
	if err != nil {
		t.Fatal(err)
	}
	readyRaw = bytes.TrimSpace(readyRaw)
	encoded := base64.RawURLEncoding.EncodeToString(readyRaw)
	arms := [2]string{
		"sha256:a954f447c1d0010a64ea0d7e9e48c029f56be8ad889a1e6708a265abda50dd59",
		"sha256:982773648e5fbc3e21f321ab7007cf211564f62b64806b2f19dc8c874cdb1777",
	}
	bridgeObserved := "sha256:" + strings.Repeat("8", 64)
	now := base.Add(3 * time.Second)
	sha, expiry, err := verifyCooperativeReady(encoded, authority, observation, arms, bridgeObserved, now)
	if err != nil || sha != digest(readyRaw) ||
		!expiry.Equal(authority.FD3.Expires) || !now.Before(expiry) {
		t.Fatalf("signed cooperative Ready refused: %v", err)
	}
	changedObservation := observation
	changedObservation.Children[1].PID++
	if _, _, err := verifyCooperativeReady(encoded, authority, changedObservation, arms,
		bridgeObserved, now); err == nil {
		t.Fatal("Ready accepted changed observed ACP child")
	}
	changedObservation = observation
	changedObservation.MapDigest = "sha256:" + strings.Repeat("0", 64)
	if _, _, err := verifyCooperativeReady(encoded, authority, changedObservation, arms,
		bridgeObserved, now); err == nil {
		t.Fatal("Ready accepted changed provisional H map")
	}
	changed := arms
	changed[0] = "sha256:" + strings.Repeat("0", 64)
	if _, _, err := verifyCooperativeReady(encoded, authority, observation, changed, bridgeObserved, now); err == nil {
		t.Fatal("Ready accepted wrong local B arm")
	}
	if _, _, err := verifyCooperativeReady(encoded, authority, observation, arms,
		"sha256:"+strings.Repeat("0", 64), now); err == nil {
		t.Fatal("Ready accepted wrong B observed digest")
	}
	if _, _, err := verifyCooperativeReady(encoded, authority, observation, arms,
		bridgeObserved, expiry); err == nil {
		t.Fatal("expired Ready accepted")
	}
	changedAuthority := authority
	changedAuthority.Assignment = map[string]any{"profile_in_force": "managed-protected"}
	if _, _, err := verifyCooperativeReady(encoded, changedAuthority, observation, arms,
		bridgeObserved, now); err == nil {
		t.Fatal("protected authority accepted cooperative Ready")
	}
}

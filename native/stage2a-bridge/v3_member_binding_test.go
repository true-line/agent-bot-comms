package main

import (
	"context"
	"encoding/base64"
	"errors"
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

func TestV3ObserveRetryCodeIsNarrow(t *testing.T) {
	const pending = `{"id":"observe-0-0","ok":false,"host_refusal":{"code":"host.launch_busy","explanation":"child observation pending","correlation_id":"test"}}`
	var out v3ObserveReply
	if err := decodeBrokerResult([]byte(pending), "observe-0-0",
		"bridge.member.observe.v3", &out); !errors.Is(err, errObservationPending) {
		t.Fatalf("pending refusal not classified: %v", err)
	}
	for _, test := range []struct {
		name string
		data string
		op   string
	}{
		{"wrong op", pending, "bridge.member.arm.v3"},
		{"authority refusal", `{"id":"observe-0-0","ok":false,"host_refusal":{"code":"host.launch_unavailable","explanation":"invalid authority","correlation_id":"test"}}`, "bridge.member.observe.v3"},
		{"internal error", `{"id":"observe-0-0","ok":false,"host_refusal":{"code":"host.internal","explanation":"failed","correlation_id":"test"}}`, "bridge.member.observe.v3"},
		{"missing correlation", `{"id":"observe-0-0","ok":false,"host_refusal":{"code":"host.launch_busy","explanation":"pending"}}`, "bridge.member.observe.v3"},
		{"wrong request id", `{"id":"other","ok":false,"host_refusal":{"code":"host.launch_busy","explanation":"pending","correlation_id":"test"}}`, "bridge.member.observe.v3"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := decodeBrokerResult([]byte(test.data), "observe-0-0", test.op, &out); err == nil || errors.Is(err, errObservationPending) {
				t.Fatalf("unsafe retry for %s: %v", test.name, err)
			}
		})
	}
}

func TestV3ObserveRetryRequiresExplicitPendingAndSettledTransport(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	attempts := 0
	reply, err := retryV3Observe(ctx, func(attempt int, out *v3ObserveReply) error {
		if attempt != attempts {
			t.Fatal("observe retry skipped or repeated an attempt")
		}
		attempts++
		if attempts < 3 {
			return errObservationPending
		}
		out.Kind = "bridge.member.observe.v3.result"
		return nil
	}, func() bool { return true })
	if err != nil || reply.Kind != "bridge.member.observe.v3.result" || attempts != 3 {
		t.Fatalf("explicit pending did not retry: %+v %v attempts=%d", reply, err, attempts)
	}
	for _, test := range []struct {
		name    string
		err     error
		settled bool
	}{
		{"other refusal", invalid, true},
		{"unsettled timeout", errObservationPending, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			_, err := retryV3Observe(ctx, func(int, *v3ObserveReply) error {
				calls++
				return test.err
			}, func() bool { return test.settled })
			if err == nil || calls != 1 {
				t.Fatalf("unsafe observe retry: calls=%d err=%v", calls, err)
			}
		})
	}
}

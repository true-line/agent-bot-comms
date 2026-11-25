package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestObservedAuthorizationRequiresMachineSignedIngress(t *testing.T) {
	data, err := os.ReadFile("testdata/local-test-golden-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Signature struct {
			PublicKey string `json:"public_key_base64url"`
		} `json:"signature"`
		Ingress struct {
			Core observedIngressCore `json:"core"`
		} `json:"ingress"`
		Authorization struct {
			EnvelopeJCS string `json:"envelope_jcs"`
			EnvelopeSHA string `json:"envelope_sha256"`
		} `json:"authorization"`
	}
	if json.Unmarshal(data, &vector) != nil {
		t.Fatal("invalid shared authorization vector")
	}
	pin, err := base64.RawURLEncoding.DecodeString(vector.Signature.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	reply := observedAuthorizationReply{
		Envelope:    base64.RawURLEncoding.EncodeToString([]byte(vector.Authorization.EnvelopeJCS)),
		EnvelopeSHA: vector.Authorization.EnvelopeSHA,
	}
	issued := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	now, assignmentExpires := issued.Add(time.Second), issued.Add(10*time.Second)
	if got, err := verifyObservedAuthorization(reply, pin, vector.Ingress.Core,
		assignmentExpires, now); err != nil || got != reply.EnvelopeSHA {
		t.Fatalf("Machine signed ingress authorization refused: %v", err)
	}
	changed := vector.Ingress.Core
	changed.ObservedBodySHA256 = "sha256:" + strings.Repeat("0", 64)
	if _, err := verifyObservedAuthorization(reply, pin, changed, assignmentExpires, now); err == nil {
		t.Fatal("HQ changed observed body digest without Machine signature")
	}
	wrongPin := append([]byte(nil), pin...)
	wrongPin[0] ^= 1
	if _, err := verifyObservedAuthorization(reply, wrongPin, vector.Ingress.Core,
		assignmentExpires, now); err == nil {
		t.Fatal("wrong Machine pin accepted")
	}
	wrongSHA := reply
	wrongSHA.EnvelopeSHA = "sha256:" + strings.Repeat("0", 64)
	if _, err := verifyObservedAuthorization(wrongSHA, pin, vector.Ingress.Core,
		assignmentExpires, now); err == nil {
		t.Fatal("wrong authorization envelope digest accepted")
	}
	if _, err := verifyObservedAuthorization(reply, pin, vector.Ingress.Core,
		assignmentExpires, issued.Add(5*time.Second)); err == nil {
		t.Fatal("expired authorization accepted")
	}
}

package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strconv"
	"strings"
	"time"
)

const v3BindContext = "agent-bot-stage2a-bridge-bind-v3"

func v3BindProof(key []byte, nonce string, f v3FD3) (string, error) {
	if len(key) != 32 || !hexPattern.MatchString(nonce) {
		return "", invalid
	}
	s := f.Selectors
	mac := hmac.New(sha256.New, key)
	_, err := io.WriteString(mac, strings.Join([]string{v3BindContext, nonce, f.Epoch,
		s.Installation, s.Start, s.Plan, s.PlanDigest, s.Reservation,
		s.AssignmentDigest, s.AuthorityDigest, s.MemberSelectorsDigest,
		strconv.FormatUint(uint64(f.BridgeUID), 10), f.Broker.Path}, "\x00"))
	if err != nil {
		return "", invalid
	}
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func (b *broker) bindV3(ctx context.Context, f v3FD3, key []byte) (string, error) {
	defer clear(key)
	var challenge challenge
	if b.call(ctx, "challenge", "bridge.bind.v3.challenge", f.Selectors, &challenge) != nil ||
		challenge.Algorithm != "hmac-sha256" || challenge.Context != v3BindContext ||
		challenge.Epoch != f.Epoch || !hexPattern.MatchString(challenge.Nonce) ||
		!time.Now().Before(challenge.Expires) || challenge.Expires.After(f.Expires) {
		return "", invalid
	}
	proof, err := v3BindProof(key, challenge.Nonce, f)
	if err != nil {
		return "", invalid
	}
	var bound struct {
		Receipt string `json:"bind_receipt"`
	}
	if b.call(ctx, "bind", "bridge.bind.v3", struct {
		v3Selectors
		Proof string `json:"proof"`
	}{f.Selectors, proof}, &bound) != nil || !hexPattern.MatchString(bound.Receipt) ||
		!time.Now().Before(challenge.Expires) || !f.Broker.current() {
		return "", invalid
	}
	return digest([]byte(bound.Receipt)), nil
}

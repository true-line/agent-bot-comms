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

const cooperativeBindContext = "agent-bot-stage2a-cooperative-bridge-bind-v3"

type cooperativeChallenge struct {
	Nonce     string    `json:"nonce"`
	Algorithm string    `json:"algorithm"`
	Context   string    `json:"context"`
	Epoch     string    `json:"hq_epoch"`
	Expires   time.Time `json:"expires_at"`
}

type cooperativeBindRequest struct {
	Nonce        string `json:"nonce"`
	Epoch        string `json:"hq_epoch"`
	Installation string `json:"installation_id"`
	Start        string `json:"start_id"`
	Launch       string `json:"launch_id"`
	Plan         string `json:"plan_id"`
	PlanDigest   string `json:"plan_digest"`
	Reservation  string `json:"reservation_sha256"`
	Assignment   string `json:"bridge_assignment_envelope_sha256"`
	BridgeUID    uint32 `json:"bridge_uid"`
	BrokerPath   string `json:"broker_socket_path"`
	Proof        string `json:"proof_hex"`
}

func cooperativeProof(key []byte, nonce string, a cooperativeBridgeAuthority) (string, error) {
	if len(key) != 32 || !hexPattern.MatchString(nonce) ||
		!validDigest(a.ReservationSHA) || !validDigest(a.AssignmentSHA) ||
		!hexPattern.MatchString(a.Epoch) || a.BrokerPath == "" {
		return "", invalid
	}
	fields := []string{cooperativeBindContext, nonce, a.Epoch, a.Installation,
		a.Start, a.Launch, a.Plan, a.PlanDigest, a.ReservationSHA,
		a.AssignmentSHA, strconv.FormatUint(uint64(a.BridgeUID), 10), a.BrokerPath}
	mac := hmac.New(sha256.New, key)
	if _, err := io.WriteString(mac, strings.Join(fields, "\x00")); err != nil {
		return "", invalid
	}
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// Both requests use the single B-client/H-server broker connection. The
// receipt digest is H's canonical bind record, later joined by A through FD5.
func (b *broker) bindCooperative(ctx context.Context, a cooperativeBridgeAuthority,
	key []byte, brokerEndpoint endpoint) (string, error) {
	defer clear(key)
	var challenge cooperativeChallenge
	if b.call(ctx, "cooperative-challenge", "bridge.bind.cooperative.v3", struct{}{}, &challenge) != nil ||
		challenge.Algorithm != "hmac-sha256" || challenge.Context != cooperativeBindContext ||
		challenge.Epoch != a.Epoch || !hexPattern.MatchString(challenge.Nonce) ||
		!time.Now().Before(challenge.Expires) || challenge.Expires.After(a.Expires) ||
		!brokerEndpoint.current() {
		return "", invalid
	}
	proof, err := cooperativeProof(key, challenge.Nonce, a)
	if err != nil {
		return "", invalid
	}
	request := cooperativeBindRequest{challenge.Nonce, a.Epoch, a.Installation,
		a.Start, a.Launch, a.Plan, a.PlanDigest, a.ReservationSHA,
		a.AssignmentSHA, a.BridgeUID, a.BrokerPath, proof}
	var result struct {
		ReceiptSHA string `json:"bind_receipt_sha256"`
	}
	if b.call(ctx, "cooperative-proof", "bridge.bind.cooperative.v3", request, &result) != nil ||
		!validDigest(result.ReceiptSHA) || !time.Now().Before(challenge.Expires) ||
		!brokerEndpoint.current() {
		return "", invalid
	}
	return result.ReceiptSHA, nil
}

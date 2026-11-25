package main

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	observedBindChallengeOp = "bridge.observed-body-local-test.bind.v1.challenge"
	observedBindOp          = "bridge.observed-body-local-test.bind.v1"
	observedIngressOp       = "bridge.observed-body-local-test.ingress.v1"
	observedPrewriteOp      = "bridge.observed-body-local-test.prewrite.v1"
	observedCompleteOp      = "bridge.observed-body-local-test.complete.v1"
)

// Inputs to this helper must come from the new Machine-signed FD3 and B
// policy verifier. The helper makes no authority decision from an H reply.
type observedBindInput struct {
	Selectors              observedSelectors
	Epoch                  string
	BridgeUID              uint32
	BrokerPath             string
	RunnerAccount          string
	ChildCWDEmitted        string
	BodyProfile            string
	StaticProjectionSHA256 string
	OwnerPromptSHA256      string
	Expires                time.Time
}

func (s observedSelectors) validate() error {
	if !idPattern.MatchString(s.InstallationID) || !startPattern.MatchString(s.StartID) ||
		!launchPattern.MatchString(s.LaunchID) || !idPattern.MatchString(s.PlanID) ||
		!hexPattern.MatchString(s.PlanDigest) || !validDigest(s.ReservationDigest) ||
		!validDigest(s.AssignmentEnvelopeSHA) || !validDigest(s.AuthorityEnvelopeSHA) ||
		!validDigest(s.MemberSelectorsSHA256) {
		return invalid
	}
	return nil
}

func (in observedBindInput) parts(nonce string) ([]string, error) {
	if in.Selectors.validate() != nil || !hexPattern.MatchString(nonce) ||
		!hexPattern.MatchString(in.Epoch) || in.BridgeUID == 0 ||
		!filepath.IsAbs(in.BrokerPath) || filepath.Clean(in.BrokerPath) != in.BrokerPath ||
		len(in.BrokerPath) > 103 || strings.ContainsAny(in.BrokerPath, "\x00\r\n") ||
		in.RunnerAccount == "" || strings.ContainsAny(in.RunnerAccount, "\x00\r\n") ||
		!filepath.IsAbs(in.ChildCWDEmitted) || filepath.Clean(in.ChildCWDEmitted) != in.ChildCWDEmitted ||
		in.BodyProfile != "stage2a-stock-observed-local-test/v1" ||
		!validDigest(in.StaticProjectionSHA256) || !validDigest(in.OwnerPromptSHA256) {
		return nil, invalid
	}
	s := in.Selectors
	return []string{observedBindContext, nonce, in.Epoch, s.InstallationID, s.StartID,
		s.LaunchID, s.PlanID, s.PlanDigest, s.ReservationDigest,
		strconv.FormatUint(uint64(in.BridgeUID), 10), in.BrokerPath,
		in.RunnerAccount, in.ChildCWDEmitted, in.BodyProfile,
		in.StaticProjectionSHA256, in.OwnerPromptSHA256}, nil
}

func (b *broker) bindObserved(ctx context.Context, in observedBindInput,
	rawFD4 []byte, current func() bool) (string, error) {
	defer clear(rawFD4)
	if b == nil || b.conn == nil || b.conn.RemoteAddr() == nil ||
		in.BrokerPath != b.conn.RemoteAddr().String() || current == nil ||
		!time.Now().Before(in.Expires) || !current() {
		return "", invalid
	}
	var challenge challenge
	if b.call(ctx, "challenge", observedBindChallengeOp, in.Selectors, &challenge) != nil ||
		challenge.Algorithm != "hmac-sha256" || challenge.Context != observedBindContext ||
		challenge.Epoch != in.Epoch || !hexPattern.MatchString(challenge.Nonce) ||
		!time.Now().Before(challenge.Expires) || challenge.Expires.After(in.Expires) || !current() {
		return "", invalid
	}
	parts, err := in.parts(challenge.Nonce)
	if err != nil {
		return "", invalid
	}
	proof, err := observedBindProof(rawFD4, parts)
	if err != nil {
		return "", invalid
	}
	var result struct {
		BindReceipt string `json:"bind_receipt"`
	}
	if b.call(ctx, "bind", observedBindOp, struct {
		Selectors observedSelectors `json:"selectors"`
		Proof     string            `json:"proof"`
	}{in.Selectors, proof}, &result) != nil || !hexPattern.MatchString(result.BindReceipt) ||
		!time.Now().Before(challenge.Expires) || !current() {
		return "", invalid
	}
	return digest([]byte(result.BindReceipt)), nil
}

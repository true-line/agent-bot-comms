package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

var errObservationPending = errors.New("signed child observation pending")

func randomNonce() (string, error) {
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}

func jcsInteger(value int64) json.Number {
	return json.Number(strconv.FormatInt(value, 10))
}

func makeV3BridgeArm(authority v3Authority, member v3Member, child v3ObservedChild,
	observation v3Observation, now time.Time) (map[string]any, string, error) {
	if !now.Before(authority.FD3.Expires) || !now.Before(observation.Expires) ||
		!validDigest(observation.EnvelopeDigest) ||
		child.MemberID != member.ID || child.Selector != member.Selector ||
		child.Launch != member.Launch || child.RuntimeID == "" ||
		child.CommandDigest != member.CommandDigest {
		return nil, "", invalid
	}
	arm := map[string]any{
		"member_id":                         child.MemberID,
		"member_selector":                   child.Selector,
		"runtime_id":                        child.RuntimeID,
		"child_observation_envelope_sha256": observation.EnvelopeDigest,
		"bridge_uid":                        jcsInteger(int64(authority.FD3.BridgeUID)),
		"adapter_pid":                       jcsInteger(child.PID),
		"adapter_uid":                       jcsInteger(int64(child.UID)),
		"adapter_gid":                       jcsInteger(int64(child.GID)),
		"adapter_start_seconds":             jcsInteger(child.StartSeconds),
		"adapter_start_micros":              jcsInteger(child.StartMicros),
		"relay_peer_rule":                   "a-attested-live-direct-child-of-adapter-v1",
		"relay_peer_state":                  "unobserved",
		"provider_ingress":                  "withheld-pending-per-peer-attestation",
		"state":                             "armed",
		"armed_at":                          now.UTC().Format(time.RFC3339Nano),
	}
	canonical, err := canonicalBytes(arm)
	if err != nil {
		return nil, "", invalid
	}
	return arm, digest(canonical), nil
}

type v3ObserveReply struct {
	Kind           string    `json:"kind"`
	MemberID       string    `json:"member_id"`
	MemberSelector string    `json:"member_selector"`
	Nonce          string    `json:"observe_nonce"`
	Envelope       string    `json:"child_observation_envelope_base64url"`
	Digest         string    `json:"child_observation_envelope_sha256"`
	Expires        time.Time `json:"expires_at"`
}

// H can return a definitive not-ready refusal while A is still observing
// two inert children. It permits the identical nonce to retry; a transport
// timeout is different, because a late reply may still occupy b.frames.
func retryV3Observe(ctx context.Context, call func(int, *v3ObserveReply) error,
	transportSettled func() bool) (v3ObserveReply, error) {
	for attempt := 0; ; attempt++ {
		var reply v3ObserveReply
		if err := call(attempt, &reply); err == nil {
			return reply, nil
		} else if !errors.Is(err, errObservationPending) {
			return v3ObserveReply{}, invalid
		}
		if ctx.Err() != nil || !transportSettled() {
			return v3ObserveReply{}, invalid
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return v3ObserveReply{}, invalid
		case <-timer.C:
		}
	}
}

// This consumes the existing v3 B→H broker stream. A successful arm reply is
// pending only; it does not open relay ingress or claim aggregate Ready.
func (b *broker) armV3Member(ctx context.Context, authority v3Authority,
	index int) (map[string]any, string, error) {
	if index < 0 || index >= len(authority.Members) {
		return nil, "", invalid
	}
	member := authority.Members[index]
	deadline := time.Now().Add(20 * time.Second)
	if authority.FD3.Expires.Before(deadline) {
		deadline = authority.FD3.Expires
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	observeNonce, err := randomNonce()
	if err != nil {
		return nil, "", invalid
	}
	observeRequest := struct {
		Kind           string      `json:"kind"`
		Selectors      v3Selectors `json:"selectors"`
		MemberID       string      `json:"member_id"`
		MemberSelector string      `json:"member_selector"`
		Nonce          string      `json:"observe_nonce"`
	}{"bridge.member.observe.v3.request", authority.FD3.Selectors, member.ID, member.Selector, observeNonce}
	observedReply, err := retryV3Observe(ctx, func(attempt int, out *v3ObserveReply) error {
		return b.call(ctx, "observe-"+strconv.Itoa(index)+"-"+strconv.Itoa(attempt),
			"bridge.member.observe.v3", observeRequest, out)
	}, func() bool { return !b.waiting.Load() })
	if err != nil || observedReply.Kind != "bridge.member.observe.v3.result" ||
		observedReply.MemberID != member.ID || observedReply.MemberSelector != member.Selector ||
		observedReply.Nonce != observeNonce || !validDigest(observedReply.Digest) ||
		!time.Now().Before(observedReply.Expires) {
		return nil, "", invalid
	}
	observation, err := verifyV3Observation(observedReply.Envelope, authority, time.Now())
	if err != nil || observation.EnvelopeDigest != observedReply.Digest ||
		observedReply.Expires.After(observation.Expires) ||
		!liveV3Child(observation.Children[index], member) {
		return nil, "", invalid
	}
	now := time.Now()
	arm, armDigest, err := makeV3BridgeArm(authority, member, observation.Children[index], observation, now)
	if err != nil {
		return nil, "", invalid
	}
	armNonce, err := randomNonce()
	if err != nil {
		return nil, "", invalid
	}
	armRequest := struct {
		Kind            string         `json:"kind"`
		Selectors       v3Selectors    `json:"selectors"`
		MemberID        string         `json:"member_id"`
		MemberSelector  string         `json:"member_selector"`
		ObserveNonce    string         `json:"observe_nonce"`
		ArmNonce        string         `json:"arm_nonce"`
		ObservationHash string         `json:"child_observation_envelope_sha256"`
		Arm             map[string]any `json:"bridge_arm"`
		ArmDigest       string         `json:"bridge_arm_receipt_sha256"`
	}{"bridge.member.arm.v3.request", authority.FD3.Selectors, member.ID, member.Selector,
		observeNonce, armNonce, observation.EnvelopeDigest, arm, armDigest}
	var reply struct {
		Kind           string    `json:"kind"`
		MemberID       string    `json:"member_id"`
		MemberSelector string    `json:"member_selector"`
		Nonce          string    `json:"arm_nonce"`
		Digest         string    `json:"bridge_arm_receipt_sha256"`
		State          string    `json:"state"`
		Expires        time.Time `json:"expires_at"`
	}
	if b.call(ctx, "arm-"+strconv.Itoa(index), "bridge.member.arm.v3", armRequest, &reply) != nil ||
		reply.Kind != "bridge.member.arm.v3.result" ||
		reply.MemberID != member.ID || reply.MemberSelector != member.Selector ||
		reply.Nonce != armNonce || reply.Digest != armDigest ||
		reply.State != "recorded-pending-aggregate-ready" ||
		!time.Now().Before(reply.Expires) || !time.Now().Before(authority.FD3.Expires) ||
		!liveV3Child(observation.Children[index], member) {
		return nil, "", invalid
	}
	return arm, armDigest, nil
}

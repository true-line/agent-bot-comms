package main

import (
	"bytes"
	"time"
)

const observedAuthorizationPurpose = "agent-bot/stage2a-observed-body-local-test-ingress-authorization/v1"

type observedAuthorizationReply struct {
	Envelope    string `json:"authorization_envelope_base64url"`
	EnvelopeSHA string `json:"authorization_envelope_sha256"`
}

// HQ only transports this reply. The separately opened Machine pin verifies
// the signature, exact ingress commitment and spent-claim attestation.
func verifyObservedAuthorization(reply observedAuthorizationReply, pin []byte,
	core observedIngressCore, assignmentExpires, now time.Time) (string, error) {
	if !validDigest(reply.EnvelopeSHA) || !now.Before(assignmentExpires) ||
		validateObservedIngressCore(core, now) != nil {
		return "", invalid
	}
	coreBytes, err := canonicalJSONValue(core)
	if err != nil {
		return "", invalid
	}
	payload, envelopeBytes, err := signedV3Payload(reply.Envelope, pin, observedAuthorizationPurpose)
	if err != nil || digest(envelopeBytes) != reply.EnvelopeSHA ||
		!exactKeys(payload, "schema", "kind", "selectors", "ingress_core_sha256",
			"provider_claim_sha256", "issued_at", "expires_at") ||
		field(payload, "schema") != "agent-bot-machine/stage2a-observed-body-local-test-ingress-authorization/v1" ||
		field(payload, "kind") != "observed-body-local-test-ingress-authorization" ||
		field(payload, "ingress_core_sha256") != digest(coreBytes) ||
		!validDigest(field(payload, "provider_claim_sha256")) {
		return "", invalid
	}
	selectors, err := canonicalBytes(payload["selectors"])
	if err != nil {
		return "", invalid
	}
	wantSelectors, err := canonicalJSONValue(core.Selectors)
	if err != nil || !bytes.Equal(selectors, wantSelectors) {
		return "", invalid
	}
	issued, err1 := time.Parse(time.RFC3339Nano, field(payload, "issued_at"))
	expires, err2 := time.Parse(time.RFC3339Nano, field(payload, "expires_at"))
	if err1 != nil || err2 != nil || now.Before(issued) || !now.Before(expires) ||
		expires.After(assignmentExpires) || !expires.After(issued) ||
		expires.Sub(issued) > 30*time.Second {
		return "", invalid
	}
	return reply.EnvelopeSHA, nil
}

func validateObservedIngressCore(core observedIngressCore, now time.Time) error {
	if core.Schema != "stage2a-observed-body-local-test-ingress/v1" ||
		core.Kind != "observed-body-local-test-ingress" ||
		core.Selectors.validate() != nil || !validDigest(core.BindReceiptSHA256) ||
		!validDigest(core.PeerSHA256) || !validDigest(core.ObservedBodySHA256) ||
		!validDigest(core.ObservedHeadersSHA256) || !validDigest(core.StaticProjectionSHA256) ||
		!validDigest(core.ObservedBriefSHA256) || !validDigest(core.OwnerPromptSHA256) ||
		core.BodyProfile != "stage2a-stock-observed-local-test/v1" ||
		core.DigestKind != "observed-stock-body/v1" || !idPattern.MatchString(core.AttemptID) ||
		core.Peer.PID <= 1 || core.Peer.PIDVersion == 0 || core.Peer.StartSeconds == 0 ||
		core.Peer.StartMicros >= 1000000 || core.Peer.ParentPID <= 1 ||
		core.Peer.ParentStartSeconds == 0 || core.Peer.ParentStartMicros >= 1000000 {
		return invalid
	}
	peerBytes, err := canonicalJSONValue(core.Peer)
	if err != nil || digest(peerBytes) != core.PeerSHA256 {
		return invalid
	}
	received, err := time.Parse(time.RFC3339Nano, core.TargetReceivedAt)
	if err != nil || now.Before(received) || now.Sub(received) > 30*time.Second {
		return invalid
	}
	return nil
}

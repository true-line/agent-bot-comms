package main

import "time"

const observedPrewriteAcceptancePurpose = "agent-bot/stage2a-observed-body-local-test-prewrite-acceptance/v1"

type observedPrewriteReply struct {
	PrewriteReceipt     string `json:"prewrite_receipt"`
	ProofEnvelope       string `json:"prewrite_proof_envelope_base64url"`
	ProofEnvelopeSHA256 string `json:"prewrite_proof_envelope_sha256"`
}

// Machine signs this only after durable acceptance. The proof commits the
// entire B prewrite core, including the exact response wire and byte count.
// HQ transports the envelope unchanged; B checks it before its first write.
func verifyObservedPrewriteProof(reply observedPrewriteReply, prewrite observedPrewrite,
	core observedIngressCore, auth observedAuthorizationReply, authority observedAuthority,
	now time.Time) error {
	if !hexPattern.MatchString(reply.PrewriteReceipt) ||
		!validDigest(reply.ProofEnvelopeSHA256) ||
		prewrite.Schema != "stage2a-observed-body-local-test-prewrite/v1" ||
		prewrite.Selectors != authority.FD3.Selectors ||
		verifyObservedPrewriteJoins(prewrite, core, auth.EnvelopeSHA) != nil ||
		!now.Before(authority.FD3.Expires) {
		return invalid
	}
	authSHA, err := verifyObservedAuthorization(auth, authority.Pin[:], core,
		authority.FD3.Expires, now)
	if err != nil || authSHA != prewrite.AuthorizationEnvelopeSHA256 {
		return invalid
	}
	authPayload, _, err := signedV3Payload(auth.Envelope, authority.Pin[:],
		observedAuthorizationPurpose)
	if err != nil {
		return invalid
	}
	authIssued, err1 := time.Parse(time.RFC3339Nano, field(authPayload, "issued_at"))
	authExpires, err2 := time.Parse(time.RFC3339Nano, field(authPayload, "expires_at"))
	if err1 != nil || err2 != nil {
		return invalid
	}
	prewriteBytes, err := canonicalJSONValue(prewrite)
	if err != nil {
		return invalid
	}
	payload, envelopeBytes, err := signedV3Payload(reply.ProofEnvelope,
		authority.Pin[:], observedPrewriteAcceptancePurpose)
	if err != nil || digest(envelopeBytes) != reply.ProofEnvelopeSHA256 ||
		!exactKeys(payload, "schema", "kind", "schema_version", "selectors", "hq_epoch",
			"authorization_envelope_sha256", "prewrite_core_sha256",
			"prewrite_receipt", "issued_at", "expires_at") ||
		field(payload, "schema") != "agent-bot-machine/stage2a-observed-body-local-test-prewrite-acceptance/v1" ||
		field(payload, "kind") != "observed-body-local-test-prewrite-acceptance" ||
		integer(payload, "schema_version") != 1 ||
		!observedSameTyped(payload["selectors"], prewrite.Selectors) ||
		field(payload, "hq_epoch") != authority.FD3.Epoch ||
		field(payload, "authorization_envelope_sha256") != auth.EnvelopeSHA ||
		field(payload, "prewrite_core_sha256") != digest(prewriteBytes) ||
		field(payload, "prewrite_receipt") != reply.PrewriteReceipt {
		return invalid
	}
	issued, err1 := time.Parse(time.RFC3339Nano, field(payload, "issued_at"))
	expires, err2 := time.Parse(time.RFC3339Nano, field(payload, "expires_at"))
	if err1 != nil || err2 != nil || issued.Before(authIssued) || now.Before(issued) ||
		!now.Before(expires) || !expires.After(issued) ||
		expires.Sub(issued) > 30*time.Second ||
		expires.After(authExpires) || expires.After(authority.FD3.Expires) {
		return invalid
	}
	return nil
}

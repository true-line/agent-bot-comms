package main

import (
	"context"
	"time"
)

// The signed prewrite proof commits the submitted core. Independently joining
// that core to the A-authorized ingress prevents a valid proof for another
// peer, bind, request, or static profile from authorizing this socket write.
func verifyObservedPrewriteJoins(prewrite observedPrewrite,
	core observedIngressCore, authorizationSHA string) error {
	coreBytes, err := canonicalJSONValue(core)
	if err != nil {
		return invalid
	}
	peerBytes, err := canonicalJSONValue(core.Peer)
	if err != nil || prewrite.Schema != "stage2a-observed-body-local-test-prewrite/v1" ||
		core.Schema != "stage2a-observed-body-local-test-ingress/v1" ||
		core.Kind != "observed-body-local-test-ingress" ||
		core.Selectors.validate() != nil || prewrite.Selectors != core.Selectors ||
		!validDigest(authorizationSHA) ||
		prewrite.AuthorizationEnvelopeSHA256 != authorizationSHA ||
		prewrite.IngressCoreSHA256 != digest(coreBytes) ||
		prewrite.BindReceiptSHA256 != core.BindReceiptSHA256 ||
		prewrite.ObservedBodySHA256 != core.ObservedBodySHA256 ||
		prewrite.ObservedHeadersSHA256 != core.ObservedHeadersSHA256 ||
		prewrite.StaticProjectionSHA256 != core.StaticProjectionSHA256 ||
		prewrite.OwnerPromptSHA256 != core.OwnerPromptSHA256 ||
		prewrite.Peer != core.Peer || prewrite.PeerSHA256 != core.PeerSHA256 ||
		core.PeerSHA256 != digest(peerBytes) ||
		!validDigest(prewrite.ResponseWireSHA256) ||
		prewrite.ResponseWireBytes <= 0 || prewrite.HTTPStatus != 200 {
		return invalid
	}
	return nil
}

func (b *broker) prewriteObserved(ctx context.Context, prewrite observedPrewrite,
	core observedIngressCore, authorized observedAuthorized,
	authority observedAuthority, current func() bool,
	attempted *bool) (observedPrewriteReply, error) {
	if b == nil || current == nil || attempted == nil || *attempted || !current() ||
		verifyObservedPrewriteJoins(prewrite, core,
			authorized.AuthorizationEnvelopeSHA256) != nil ||
		prewrite.Selectors != authority.FD3.Selectors {
		return observedPrewriteReply{}, invalid
	}
	if _, err := verifyObservedAuthorization(authorized.Result.observedAuthorizationReply,
		authority.Pin[:], core, authority.FD3.Expires, time.Now()); err != nil {
		return observedPrewriteReply{}, invalid
	}
	*attempted = true
	var reply observedPrewriteReply
	if b.call(ctx, "prewrite", observedPrewriteOp, prewrite, &reply) != nil ||
		!current() || verifyObservedPrewriteProof(reply, prewrite, core,
		authorized.Result.observedAuthorizationReply, authority, time.Now()) != nil {
		return observedPrewriteReply{}, invalid
	}
	return reply, nil
}

func buildObservedPrewrite(core observedIngressCore, authorized observedAuthorized,
	prepared preparedHTTP, now time.Time) (observedPrewrite, error) {
	if validateObservedIngressCore(core, now) != nil ||
		!validDigest(authorized.AuthorizationEnvelopeSHA256) ||
		!validDigest(authorized.IngressCoreSHA256) ||
		!validDigest(prepared.SHA256) || prepared.Bytes <= 0 ||
		len(prepared.Wire) != prepared.Bytes || digest(prepared.Wire) != prepared.SHA256 ||
		prepared.Status != 200 {
		return observedPrewrite{}, invalid
	}
	coreBytes, err := canonicalJSONValue(core)
	if err != nil || digest(coreBytes) != authorized.IngressCoreSHA256 {
		return observedPrewrite{}, invalid
	}
	prewrite := observedPrewrite{
		Schema:    "stage2a-observed-body-local-test-prewrite/v1",
		Selectors: core.Selectors, BindReceiptSHA256: core.BindReceiptSHA256,
		AuthorizationEnvelopeSHA256: authorized.AuthorizationEnvelopeSHA256,
		IngressCoreSHA256:           authorized.IngressCoreSHA256,
		ObservedBodySHA256:          core.ObservedBodySHA256,
		ObservedHeadersSHA256:       core.ObservedHeadersSHA256,
		StaticProjectionSHA256:      core.StaticProjectionSHA256,
		OwnerPromptSHA256:           core.OwnerPromptSHA256,
		Peer:                        core.Peer, PeerSHA256: core.PeerSHA256,
		ResponseWireSHA256: prepared.SHA256, ResponseWireBytes: prepared.Bytes,
		HTTPStatus: prepared.Status,
	}
	if verifyObservedPrewriteJoins(prewrite, core,
		authorized.AuthorizationEnvelopeSHA256) != nil {
		return observedPrewrite{}, invalid
	}
	return prewrite, nil
}

func buildObservedCompletion(prewrite observedPrewrite, receipt string,
	written httpWrite) (observedCompletionCore, error) {
	if prewrite.Schema != "stage2a-observed-body-local-test-prewrite/v1" ||
		!hexPattern.MatchString(receipt) || !validDigest(prewrite.AuthorizationEnvelopeSHA256) ||
		!validDigest(prewrite.IngressCoreSHA256) || !validDigest(prewrite.ResponseWireSHA256) ||
		prewrite.ResponseWireBytes <= 0 || prewrite.HTTPStatus != 200 ||
		written.SHA256 != prewrite.ResponseWireSHA256 || written.Bytes != prewrite.ResponseWireBytes ||
		written.Status != prewrite.HTTPStatus || written.StartedAt.IsZero() ||
		written.CompletedAt.IsZero() || written.CompletedAt.Before(written.StartedAt) {
		return observedCompletionCore{}, invalid
	}
	prewrite.Schema = "stage2a-observed-body-local-test-completion/v1"
	return observedCompletionCore{
		observedPrewrite: prewrite,
		PrewriteReceipt:  receipt,
		WriteStartedAt:   written.StartedAt.UTC().Format(time.RFC3339Nano),
		WriteCompletedAt: written.CompletedAt.UTC().Format(time.RFC3339Nano),
		DigestKind:       "observed-stock-body/v1",
	}, nil
}

// Completion MACs the full successful write under its own FD4-derived key.
// The public bind proof and the earlier ingress MAC cannot seal this record.
func sealObservedCompletion(core observedCompletionCore, completionKey []byte,
	attempted *bool) (observedCompletionPayload, error) {
	defer clear(completionKey)
	if attempted == nil || *attempted ||
		core.Schema != "stage2a-observed-body-local-test-completion/v1" ||
		core.DigestKind != "observed-stock-body/v1" ||
		!hexPattern.MatchString(core.PrewriteReceipt) ||
		!validDigest(core.ResponseWireSHA256) || core.ResponseWireBytes <= 0 ||
		core.HTTPStatus != 200 || len(completionKey) != 32 {
		return observedCompletionPayload{}, invalid
	}
	*attempted = true
	mac, err := observedOriginMAC(completionKey, observedCompleteOriginContext, core)
	if err != nil {
		return observedCompletionPayload{}, invalid
	}
	return observedCompletionPayload{Core: core, CompletionOriginMAC: mac}, nil
}

// H must relay this acknowledgement only after Machine accepts the B-origin
// completion MAC and persists the immutable completed run. B checks every
// available echo; independent A readback still determines acceptance credit.
func (b *broker) completeObserved(ctx context.Context, sealed observedCompletionPayload,
	current func() bool) error {
	if b == nil || current == nil || !current() ||
		sealed.Core.Schema != "stage2a-observed-body-local-test-completion/v1" ||
		!hexPattern.MatchString(sealed.CompletionOriginMAC) {
		return invalid
	}
	completionBytes, err := canonicalJSONValue(sealed.Core)
	if err != nil {
		return invalid
	}
	var ack struct {
		Accepted                    bool              `json:"accepted"`
		Selectors                   observedSelectors `json:"selectors"`
		ObservedBodySHA256          string            `json:"observed_body_sha256"`
		AuthorizationEnvelopeSHA256 string            `json:"authorization_envelope_sha256"`
		CompletionCoreSHA256        string            `json:"completion_core_sha256"`
		CompletedRunSHA256          string            `json:"completed_run_sha256"`
	}
	if b.call(ctx, "complete", observedCompleteOp, sealed, &ack) != nil ||
		!ack.Accepted || ack.Selectors != sealed.Core.Selectors ||
		ack.ObservedBodySHA256 != sealed.Core.ObservedBodySHA256 ||
		ack.AuthorizationEnvelopeSHA256 != sealed.Core.AuthorizationEnvelopeSHA256 ||
		ack.CompletionCoreSHA256 != digest(completionBytes) ||
		!validDigest(ack.CompletedRunSHA256) || !current() {
		return invalid
	}
	return nil
}

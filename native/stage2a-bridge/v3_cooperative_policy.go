package main

import (
	"context"
	"crypto/ed25519"
	"time"
)

type cooperativePolicyWire struct {
	AssignmentEnvelope string `json:"member_set_assignment_envelope_base64url"`
	AssignmentSHA      string `json:"member_set_assignment_envelope_sha256"`
	AuthorityEnvelope  string `json:"member_b_authority_envelope_base64url"`
	AuthoritySHA       string `json:"member_b_authority_envelope_sha256"`
}

func (b *broker) cooperativeMemberPolicy(ctx context.Context,
	a cooperativeBridgeAuthority, pin []byte, brokerEndpoint, relayEndpoint endpoint) (v3Authority, error) {
	var result cooperativePolicyWire
	request := struct {
		ReservationSHA string `json:"reservation_sha256"`
		AssignmentSHA  string `json:"bridge_assignment_envelope_sha256"`
	}{a.ReservationSHA, a.AssignmentSHA}
	if !cooperativeEndpointCurrent(a.BrokerRecord, brokerEndpoint) ||
		b.call(ctx, "cooperative-member-policy", "bridge.member-policy.v3", request, &result) != nil ||
		!cooperativeEndpointCurrent(a.BrokerRecord, brokerEndpoint) {
		return v3Authority{}, invalid
	}
	return verifyCooperativePolicy(result, a, pin, brokerEndpoint, relayEndpoint, time.Now())
}

func verifyCooperativePolicy(result cooperativePolicyWire, a cooperativeBridgeAuthority,
	pin []byte, brokerEndpoint, relayEndpoint endpoint, now time.Time) (v3Authority, error) {
	if len(pin) != ed25519.PublicKeySize || !now.Before(a.Expires) ||
		!validDigest(result.AssignmentSHA) || !validDigest(result.AuthoritySHA) {
		return v3Authority{}, invalid
	}
	assignmentBytes, err := unpadded(result.AssignmentEnvelope, 16384)
	if err != nil || digest(assignmentBytes) != result.AssignmentSHA {
		return v3Authority{}, invalid
	}
	authorityBytes, err := unpadded(result.AuthorityEnvelope, 16384)
	if err != nil || digest(authorityBytes) != result.AuthoritySHA {
		return v3Authority{}, invalid
	}
	assignment, parsedAssignment, err := signedV3Payload(result.AssignmentEnvelope, pin, v3AssignmentPurpose)
	if err != nil || digest(parsedAssignment) != result.AssignmentSHA ||
		field(assignment, "host_id") != a.HostID || field(assignment, "soul_id") != a.SoulID {
		return v3Authority{}, invalid
	}
	authority, parsedAuthority, err := signedV3Payload(result.AuthorityEnvelope, pin, v3AuthorityPurpose)
	if err != nil || digest(parsedAuthority) != result.AuthoritySHA ||
		field(authority, "host_id") != a.HostID || field(authority, "soul_id") != a.SoulID {
		return v3Authority{}, invalid
	}
	memberRows, ok := array(assignment["members"])
	if !ok || len(memberRows) != 2 {
		return v3Authority{}, invalid
	}
	selectors := make([]any, 2)
	for i, row := range memberRows {
		member, ok := object(row)
		if !ok || !selectorPattern.MatchString(field(member, "member_selector")) {
			return v3Authority{}, invalid
		}
		selectors[i] = field(member, "member_selector")
	}
	selectorBytes, err := canonicalBytes(selectors)
	if err != nil {
		return v3Authority{}, invalid
	}
	assignmentExpiry, e1 := time.Parse(time.RFC3339Nano, field(assignment, "expires_at"))
	authorityExpiry, e2 := time.Parse(time.RFC3339Nano, field(authority, "expires_at"))
	if e1 != nil || e2 != nil || !now.Before(assignmentExpiry) || !now.Before(authorityExpiry) {
		return v3Authority{}, invalid
	}
	expires := a.Expires
	if assignmentExpiry.Before(expires) {
		expires = assignmentExpiry
	}
	if authorityExpiry.Before(expires) {
		expires = authorityExpiry
	}
	frame := v3FD3{Version: v3Version, MachinePinPath: v3PinPath,
		AssignmentEnvelope: result.AssignmentEnvelope, AuthorityEnvelope: result.AuthorityEnvelope,
		Selectors: v3Selectors{Installation: a.Installation, Start: a.Start,
			Plan: a.Plan, PlanDigest: a.PlanDigest, Reservation: a.ReservationSHA,
			AssignmentDigest: result.AssignmentSHA, AuthorityDigest: result.AuthoritySHA,
			MemberSelectorsDigest: digest(selectorBytes)},
		Epoch: a.Epoch, BridgeUID: a.BridgeUID, HQUID: a.HQUID,
		RunnerUID: a.RunnerUID, Expires: expires, Broker: brokerEndpoint,
		Relay: relayEndpoint}
	verified, err := verifyMemberPolicy(frame, pin, now, &a)
	if err != nil {
		return v3Authority{}, invalid
	}
	// The signed member policy is an A artifact. The faked in-memory v3 FD3
	// above only reuses the protected member verifier; it never replaces A's
	// cooperative FD3 or changes the protected launch profile.
	return verified, nil
}

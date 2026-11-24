package main

import (
	"context"
	"strconv"
	"time"
)

const cooperativeBLivePurpose = "agent-bot/soul-cooperative-b-live-lease/v3"

type cooperativeBLive struct {
	SHA       string
	Sequence  int64
	Issued    time.Time
	Expires   time.Time
	ExpiresAt string
}

func (b *broker) renewCooperativeBLive(ctx context.Context, a cooperativeBridgeAuthority,
	policy v3Authority, state cooperativeReadyState, relay endpoint) (cooperativeBLive, error) {
	prior := state.Lease
	if !time.Now().Before(prior.Expires) || !time.Now().Before(state.Expires) ||
		!cooperativeEndpointCurrent(a.BrokerRecord, policy.FD3.Broker) ||
		!cooperativeEndpointCurrent(a.RelayRecord, relay) ||
		currentCooperativeRelayBirth(relay, state.BirthNS) != nil {
		return cooperativeBLive{}, invalid
	}
	nonce, err := randomBase64Nonce()
	if err != nil {
		return cooperativeBLive{}, invalid
	}
	request := struct {
		ReadySHA      string `json:"ready_envelope_sha256"`
		AfterSequence int64  `json:"after_sequence"`
		PriorExpires  string `json:"prior_expires_at"`
		Nonce         string `json:"challenge_nonce_base64url"`
	}{state.SHA, prior.Sequence, prior.ExpiresAt, nonce}
	var result struct {
		Envelope string `json:"lease_envelope_base64url"`
		SHA      string `json:"lease_sha256"`
		Sequence int64  `json:"lease_sequence"`
	}
	if b.call(ctx, "cooperative-live-"+strconv.FormatInt(prior.Sequence, 10),
		"bridge.live.cooperative.v3", request, &result) != nil ||
		!time.Now().Before(prior.Expires) ||
		!cooperativeEndpointCurrent(a.BrokerRecord, policy.FD3.Broker) ||
		!cooperativeEndpointCurrent(a.RelayRecord, relay) ||
		currentCooperativeRelayBirth(relay, state.BirthNS) != nil {
		return cooperativeBLive{}, invalid
	}
	lease, err := verifyCooperativeBLive(result.Envelope, a, policy, state.Observed,
		state.SHA, nonce, prior.Sequence, state.Expires, relay, time.Now(),
		func(e endpoint) bool { return cooperativeEndpointCurrent(a.RelayRecord, e) },
		cooperativeSelfMatches)
	if err != nil || result.SHA != lease.SHA || result.Sequence != lease.Sequence ||
		!lease.Expires.After(prior.Expires) ||
		currentCooperativeRelayBirth(relay, state.BirthNS) != nil {
		return cooperativeBLive{}, invalid
	}
	return lease, nil
}

func relayClaimValue(relay endpoint) map[string]any {
	return map[string]any{"path": relay.Path, "socket": map[string]any{
		"uid":    jcsInteger(int64(relay.Socket.UID)),
		"gid":    jcsInteger(int64(relay.Socket.GID)),
		"device": strconv.FormatUint(relay.Socket.Device, 10),
		"inode":  strconv.FormatUint(relay.Socket.Inode, 10),
		"mode":   jcsInteger(int64(relay.Socket.Mode)),
	}}
}

// A's short lease proves a fresh B/relay recheck for this exact Ready. It
// does not authorize a CLI socket; that needs a separate member lease and
// per-peer A warrant on each request.
func verifyCooperativeBLive(encoded string, a cooperativeBridgeAuthority,
	policy v3Authority, observed cooperativeObservedB, readySHA, nonce string,
	afterSequence int64, readyExpiry time.Time, relay endpoint, now time.Time,
	endpointCurrent func(endpoint) bool,
	selfMatches func(bridge, launcher map[string]any) bool) (cooperativeBLive, error) {
	raw, err := unpadded(encoded, 8192)
	nonceBytes, nonceErr := unpadded(nonce, 32)
	if err != nil || !validDigest(readySHA) || !validDigest(observed.SHA) ||
		nonceErr != nil || len(nonceBytes) != 32 ||
		endpointCurrent == nil || !endpointCurrent(relay) ||
		selfMatches == nil || !selfMatches(observed.Bridge, observed.Launcher) ||
		afterSequence < 0 || afterSequence >= (1<<53)-1 {
		return cooperativeBLive{}, invalid
	}
	p, err := signedCooperativePayload(raw, policy.Pin[:], cooperativeBLivePurpose)
	if err != nil || !exactKeys(p, "contract", "kind", "schema_version",
		"profile_in_force", "host_id", "installation_id", "start_id", "launch_id",
		"plan_id", "plan_digest", "hq_epoch", "reservation_sha256",
		"bridge_assignment_sha256", "assignment_envelope_sha256",
		"member_b_authority_envelope_sha256", "bridge_observed_sha256",
		"ready_sha256", "bridge_process", "relay_socket",
		"challenge_nonce_base64url", "sequence", "issued_at", "expires_at") ||
		field(p, "contract") != "machine/v3" ||
		field(p, "kind") != "soul-cooperative-b-live-lease" ||
		integer(p, "schema_version") != 3 ||
		field(p, "profile_in_force") != "managed-cooperative" ||
		field(p, "host_id") != a.HostID ||
		field(p, "installation_id") != a.Installation ||
		field(p, "start_id") != a.Start ||
		field(p, "launch_id") != a.Launch ||
		field(p, "plan_id") != a.Plan ||
		field(p, "plan_digest") != a.PlanDigest ||
		field(p, "hq_epoch") != a.Epoch ||
		field(p, "reservation_sha256") != a.ReservationSHA ||
		field(p, "bridge_assignment_sha256") != a.AssignmentSHA ||
		field(p, "assignment_envelope_sha256") != policy.FD3.Selectors.AssignmentDigest ||
		field(p, "member_b_authority_envelope_sha256") != policy.FD3.Selectors.AuthorityDigest ||
		field(p, "bridge_observed_sha256") != observed.SHA ||
		field(p, "ready_sha256") != readySHA ||
		field(p, "challenge_nonce_base64url") != nonce ||
		integer(p, "sequence") != afterSequence+1 ||
		!sameValue(p["bridge_process"], observed.Bridge) ||
		!sameValue(p["relay_socket"], relayClaimValue(relay)) {
		return cooperativeBLive{}, invalid
	}
	issued, e1 := time.Parse(time.RFC3339Nano, field(p, "issued_at"))
	expires, e2 := time.Parse(time.RFC3339Nano, field(p, "expires_at"))
	if e1 != nil || e2 != nil || issued.After(now) || !issued.Before(expires) ||
		!now.Before(expires) || expires.Sub(issued) > 5*time.Second ||
		expires.After(readyExpiry) || expires.After(observed.Expires) {
		return cooperativeBLive{}, invalid
	}
	return cooperativeBLive{digest(raw), afterSequence + 1, issued, expires,
		field(p, "expires_at")}, nil
}

package main

import (
	"strconv"
	"time"
)

const cooperativeRelayPeerPurpose = "agent-bot/soul-cooperative-relay-peer/v3"

type cooperativePeerWarrant struct {
	SHA     string
	Expires time.Time
}

// The accepted socket's audit token and live parent must select exactly one
// A-observed ACP child. A separately rechecks the same relationship before
// signing a short warrant for the stock Claude CLI peer.
func cooperativePeerMember(policy v3Authority, observation v3Observation,
	peer peerProcessSnapshot) (int, error) {
	selected := -1
	if peer.Peer.PID <= 1 || peer.Peer.PIDVersion <= 0 ||
		peer.StartSeconds == 0 || peer.StartMicros >= 1000000 ||
		peer.ParentPID <= 1 || peer.ParentStartSeconds == 0 ||
		peer.ParentStartMicros >= 1000000 {
		return -1, invalid
	}
	for i, child := range observation.Children {
		if child.PID == int64(peer.ParentPID) && child.UID == peer.ParentUID &&
			child.UID == peer.Peer.UID && child.StartSeconds == int64(peer.ParentStartSeconds) &&
			child.StartMicros == int64(peer.ParentStartMicros) &&
			child.MemberID == policy.Members[i].ID && child.Launch == policy.Members[i].Launch &&
			child.Selector == policy.Members[i].Selector &&
			child.CommandDigest == policy.Members[i].CommandDigest {
			if selected >= 0 {
				return -1, invalid
			}
			selected = i
		}
	}
	if selected < 0 {
		return -1, invalid
	}
	return selected, nil
}

func cooperativePeerValue(peer peerProcessSnapshot) map[string]any {
	return map[string]any{
		"uid": jcsInteger(int64(peer.Peer.UID)), "pid": jcsInteger(int64(peer.Peer.PID)),
		"pid_version":          jcsInteger(int64(peer.Peer.PIDVersion)),
		"start_seconds":        jcsInteger(int64(peer.StartSeconds)),
		"start_micros":         jcsInteger(int64(peer.StartMicros)),
		"parent_pid":           jcsInteger(int64(peer.ParentPID)),
		"parent_uid":           jcsInteger(int64(peer.ParentUID)),
		"parent_start_seconds": jcsInteger(int64(peer.ParentStartSeconds)),
		"parent_start_micros":  jcsInteger(int64(peer.ParentStartMicros)),
	}
}

func cooperativeAdapterValue(child v3ObservedChild) map[string]any {
	return map[string]any{
		"pid": jcsInteger(child.PID), "uid": jcsInteger(int64(child.UID)),
		"gid": jcsInteger(int64(child.GID)), "parent_pid": jcsInteger(child.ParentPID),
		"process_group_id":  jcsInteger(child.ProcessGroup),
		"start_seconds":     jcsInteger(child.StartSeconds),
		"start_micros":      jcsInteger(child.StartMicros),
		"executable_sha256": child.CommandDigest,
	}
}

func verifyCooperativeRelayPeer(encoded string, a cooperativeBridgeAuthority,
	policy v3Authority, observation v3Observation, ready cooperativeReadyState,
	memberLease cooperativeMemberLease, memberIndex int, peer peerProcessSnapshot,
	nonce string, relay endpoint, now time.Time) (cooperativePeerWarrant, error) {
	if memberIndex < 0 || memberIndex >= len(policy.Members) ||
		!validDigest(ready.SHA) || !validDigest(ready.Observed.SHA) ||
		!validDigest(ready.Lease.SHA) || !validDigest(memberLease.SHA) ||
		!now.Before(ready.Expires) || !now.Before(ready.Lease.Expires) ||
		!now.Before(memberLease.Expires) || ready.BirthNS <= 0 ||
		!cooperativeEndpointIdentityMatches(a.RelayRecord, relay, true) {
		return cooperativePeerWarrant{}, invalid
	}
	selected, err := cooperativePeerMember(policy, observation, peer)
	if err != nil || selected != memberIndex {
		return cooperativePeerWarrant{}, invalid
	}
	nonceBytes, err := unpadded(nonce, 32)
	if err != nil || len(nonceBytes) != 32 {
		return cooperativePeerWarrant{}, invalid
	}
	raw, err := unpadded(encoded, 8192)
	if err != nil {
		return cooperativePeerWarrant{}, invalid
	}
	p, err := signedCooperativePayload(raw, policy.Pin[:], cooperativeRelayPeerPurpose)
	if err != nil || !exactKeys(p, "contract", "kind", "schema_version", "profile_in_force",
		"host_id", "installation_id", "start_id", "launch_id", "hq_epoch",
		"reservation_sha256", "assignment_envelope_sha256",
		"member_b_authority_envelope_sha256", "bridge_observed_sha256", "ready_sha256",
		"b_lease_sha256", "b_lease_sequence", "member_lease_sha256", "member_lease_sequence",
		"member_id", "member_launch_id", "member_selector", "bridge_process",
		"adapter_process", "relay_socket", "relay_socket_birthtime_ns",
		"cli_path", "cli_sha256", "peer", "challenge_nonce_base64url",
		"issued_at", "expires_at") ||
		field(p, "contract") != "machine/v3" ||
		field(p, "kind") != "soul-cooperative-relay-peer" ||
		integer(p, "schema_version") != 3 ||
		field(p, "profile_in_force") != "managed-cooperative" ||
		field(p, "host_id") != a.HostID ||
		field(p, "installation_id") != a.Installation ||
		field(p, "start_id") != a.Start || field(p, "launch_id") != a.Launch ||
		field(p, "hq_epoch") != a.Epoch ||
		field(p, "reservation_sha256") != a.ReservationSHA ||
		field(p, "assignment_envelope_sha256") != policy.FD3.Selectors.AssignmentDigest ||
		field(p, "member_b_authority_envelope_sha256") != policy.FD3.Selectors.AuthorityDigest ||
		field(p, "bridge_observed_sha256") != ready.Observed.SHA ||
		field(p, "ready_sha256") != ready.SHA ||
		field(p, "b_lease_sha256") != ready.Lease.SHA ||
		integer(p, "b_lease_sequence") != ready.Lease.Sequence ||
		field(p, "member_lease_sha256") != memberLease.SHA ||
		integer(p, "member_lease_sequence") != memberLease.Sequence ||
		field(p, "member_id") != policy.Members[memberIndex].ID ||
		field(p, "member_launch_id") != policy.Members[memberIndex].Launch ||
		field(p, "member_selector") != policy.Members[memberIndex].Selector ||
		field(p, "cli_path") != policy.Members[memberIndex].CLIPath ||
		field(p, "cli_sha256") != policy.Members[memberIndex].CLIDigest ||
		field(p, "relay_socket_birthtime_ns") != strconv.FormatInt(ready.BirthNS, 10) ||
		field(p, "challenge_nonce_base64url") != nonce ||
		!sameValue(p["bridge_process"], ready.Observed.Bridge) ||
		!sameValue(p["adapter_process"], cooperativeAdapterValue(observation.Children[memberIndex])) ||
		!sameValue(p["relay_socket"], relayClaimValue(relay)) ||
		!sameValue(p["peer"], cooperativePeerValue(peer)) {
		return cooperativePeerWarrant{}, invalid
	}
	issued, e1 := time.Parse(time.RFC3339Nano, field(p, "issued_at"))
	expires, e2 := time.Parse(time.RFC3339Nano, field(p, "expires_at"))
	if e1 != nil || e2 != nil || issued.After(now) || !issued.Before(expires) ||
		!now.Before(expires) || expires.Sub(issued) > 5*time.Second ||
		expires.After(ready.Expires) || expires.After(ready.Lease.Expires) ||
		expires.After(memberLease.Expires) {
		return cooperativePeerWarrant{}, invalid
	}
	return cooperativePeerWarrant{digest(raw), expires}, nil
}

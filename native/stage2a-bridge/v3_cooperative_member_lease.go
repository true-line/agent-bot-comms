package main

import (
	"time"
)

const cooperativeMemberLivePurpose = "agent-bot/soul-cooperative-member-live-lease/v3"

type cooperativeMemberLease struct {
	SHA      string
	Sequence int64
	Expires  time.Time
}

// H and the member exchange their own fresh challenge and may renew before B
// sees a CLI socket. Several rotating CLI peers may use the same current
// lease. B permits that exact digest, rejects lower or changed equal-sequence
// leases, and relies on H's independent challenge continuity and A's fresh
// per-peer warrant before any ingress can be attempted.
func verifyCooperativeMemberLease(encoded string, policy v3Authority,
	observation v3Observation, memberIndex int, readySHA string,
	priorSequence int64, priorSHA string, readyExpiry, now time.Time) (cooperativeMemberLease, error) {
	if memberIndex < 0 || memberIndex >= len(policy.Members) ||
		!validDigest(readySHA) || !now.Before(readyExpiry) ||
		priorSequence < 0 || priorSequence >= 1<<53-1 {
		return cooperativeMemberLease{}, invalid
	}
	raw, err := unpadded(encoded, 8192)
	if err != nil {
		return cooperativeMemberLease{}, invalid
	}
	p, err := signedCooperativePayload(raw, policy.Pin[:], cooperativeMemberLivePurpose)
	if err != nil || !exactKeys(p, "contract", "kind", "schema_version", "profile_in_force",
		"reservation_sha256", "assignment_envelope_sha256", "ready_envelope_sha256",
		"member_id", "member_launch_id", "member_selector", "grant_sha256",
		"launcher_process", "child_process", "challenge_nonce_base64url",
		"sequence", "issued_at", "expires_at") ||
		field(p, "contract") != "machine/v3" ||
		field(p, "kind") != "soul-cooperative-member-live-lease" ||
		integer(p, "schema_version") != 3 ||
		field(p, "profile_in_force") != "managed-cooperative" ||
		field(p, "reservation_sha256") != policy.FD3.Selectors.Reservation ||
		field(p, "assignment_envelope_sha256") != policy.FD3.Selectors.AssignmentDigest ||
		field(p, "ready_envelope_sha256") != readySHA ||
		field(p, "member_id") != policy.Members[memberIndex].ID ||
		field(p, "member_launch_id") != policy.Members[memberIndex].Launch ||
		field(p, "member_selector") != policy.Members[memberIndex].Selector ||
		field(p, "grant_sha256") != observation.Children[memberIndex].GrantDigest ||
		integer(p, "sequence") <= 0 ||
		integer(p, "sequence") >= 1<<53 {
		return cooperativeMemberLease{}, invalid
	}
	nonce, err := unpadded(field(p, "challenge_nonce_base64url"), 32)
	if err != nil || len(nonce) != 32 {
		return cooperativeMemberLease{}, invalid
	}
	child := observation.Children[memberIndex]
	launcher := map[string]any{
		"pid":           jcsInteger(child.LauncherPID),
		"uid":           jcsInteger(int64(child.LauncherUID)),
		"gid":           jcsInteger(int64(child.LauncherGID)),
		"start_seconds": jcsInteger(child.LauncherStartSeconds),
		"start_micros":  jcsInteger(child.LauncherStartMicros),
	}
	process := map[string]any{
		"pid":               jcsInteger(child.PID),
		"uid":               jcsInteger(int64(child.UID)),
		"gid":               jcsInteger(int64(child.GID)),
		"parent_pid":        jcsInteger(child.ParentPID),
		"process_group_id":  jcsInteger(child.ProcessGroup),
		"start_seconds":     jcsInteger(child.StartSeconds),
		"start_micros":      jcsInteger(child.StartMicros),
		"executable_sha256": child.CommandDigest,
	}
	if !sameValue(p["launcher_process"], launcher) ||
		!sameValue(p["child_process"], process) {
		return cooperativeMemberLease{}, invalid
	}
	issued, e1 := time.Parse(time.RFC3339Nano, field(p, "issued_at"))
	expires, e2 := time.Parse(time.RFC3339Nano, field(p, "expires_at"))
	if e1 != nil || e2 != nil || issued.After(now) || !issued.Before(expires) ||
		!now.Before(expires) || expires.Sub(issued) > 5*time.Second ||
		expires.After(readyExpiry) || expires.After(observation.Expires) {
		return cooperativeMemberLease{}, invalid
	}
	sha, sequence := digest(raw), integer(p, "sequence")
	if sequence < priorSequence || (sequence == priorSequence && sha != priorSHA) {
		return cooperativeMemberLease{}, invalid
	}
	return cooperativeMemberLease{sha, sequence, expires}, nil
}

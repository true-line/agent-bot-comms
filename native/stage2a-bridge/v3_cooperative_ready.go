package main

import (
	"time"
)

const cooperativeReadyPurpose = "agent-bot/soul-cooperative-member-ready/v3"

// The A signature joins B's two exact provisional arm rows to the observed
// ACP children. It is not a lease or a per-CLI-peer authorization.
func verifyCooperativeReady(encoded string, authority v3Authority,
	observation v3Observation, armDigests [2]string, bridgeObservedSHA string,
	now time.Time) (string, time.Time, error) {
	var empty time.Time
	raw, err := unpadded(encoded, 16384)
	if err != nil || !validDigest(bridgeObservedSHA) ||
		field(authority.Assignment, "profile_in_force") != "managed-cooperative" {
		return "", empty, invalid
	}
	ready, err := signedCooperativePayload(raw, authority.Pin[:], cooperativeReadyPurpose)
	if err != nil || !exactKeys(ready, "contract", "kind", "schema_version",
		"profile_in_force", "host_id", "installation_id", "start_id", "hq_epoch",
		"reservation_sha256", "assignment_envelope_sha256",
		"child_observation_envelope_sha256", "provisional_hq_mapping_sha256",
		"member_b_authority_envelope_sha256", "bridge_observed_sha256",
		"members", "issued_at", "expires_at") ||
		field(ready, "contract") != "machine/v3" ||
		field(ready, "kind") != "soul-cooperative-member-ready" ||
		integer(ready, "schema_version") != 3 ||
		field(ready, "profile_in_force") != "managed-cooperative" {
		return "", empty, invalid
	}
	for _, key := range []string{"host_id", "installation_id", "start_id", "hq_epoch",
		"reservation_sha256"} {
		if field(ready, key) == "" || field(ready, key) != field(authority.Assignment, key) {
			return "", empty, invalid
		}
	}
	if field(ready, "assignment_envelope_sha256") != authority.FD3.Selectors.AssignmentDigest ||
		field(ready, "member_b_authority_envelope_sha256") != authority.FD3.Selectors.AuthorityDigest ||
		field(ready, "child_observation_envelope_sha256") != observation.EnvelopeDigest ||
		field(ready, "provisional_hq_mapping_sha256") != observation.MapDigest ||
		field(ready, "bridge_observed_sha256") != bridgeObservedSHA {
		return "", empty, invalid
	}
	issued, e1 := time.Parse(time.RFC3339Nano, field(ready, "issued_at"))
	expires, e2 := time.Parse(time.RFC3339Nano, field(ready, "expires_at"))
	if e1 != nil || e2 != nil || issued.After(now) || !issued.Before(expires) ||
		!now.Before(expires) || !now.Before(authority.FD3.Expires) ||
		!now.Before(observation.Expires) {
		return "", empty, invalid
	}
	// A's Ready may outlive the earlier B authority by a small amount. It
	// cannot extend either the authority or the child observation.
	if authority.FD3.Expires.Before(expires) {
		expires = authority.FD3.Expires
	}
	if observation.Expires.Before(expires) {
		expires = observation.Expires
	}
	rows, ok := array(ready["members"])
	if !ok || len(rows) != 2 {
		return "", empty, invalid
	}
	for i, value := range rows {
		row, ok := object(value)
		if !ok || !exactKeys(row, "member_id", "member_launch_id", "member_selector",
			"grant_sha256", "launcher_process", "child_process",
			"h_observation_sha256", "b_arm_receipt_sha256") ||
			field(row, "member_id") != authority.Members[i].ID ||
			field(row, "member_launch_id") != authority.Members[i].Launch ||
			field(row, "member_selector") != authority.Members[i].Selector ||
			field(row, "grant_sha256") != observation.Children[i].GrantDigest ||
			!validDigest(field(row, "h_observation_sha256")) ||
			!validDigest(armDigests[i]) ||
			field(row, "b_arm_receipt_sha256") != armDigests[i] {
			return "", empty, invalid
		}
		child := observation.Children[i]
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
		if !sameValue(row["launcher_process"], launcher) ||
			!sameValue(row["child_process"], process) {
			return "", empty, invalid
		}
	}
	return digest(raw), expires, nil
}

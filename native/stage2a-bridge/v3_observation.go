package main

import (
	"time"
)

const v3ObservationPurpose = "agent-bot/stage2a-member-set-child-observation/v1"

type v3ObservedChild struct {
	MemberID      string
	Selector      string
	Launch        string
	RuntimeID     string
	PID           int64
	UID           uint32
	GID           uint32
	ParentPID     int64
	ProcessGroup  int64
	StartSeconds  int64
	StartMicros   int64
	CommandDigest string
}

type v3Observation struct {
	EnvelopeDigest string
	MapDigest      string
	Expires        time.Time
	Children       [2]v3ObservedChild
}

// Verify the A-signed two-child observation before either B member arm.
// This is a signature and immutable-join check. The caller must separately
// compare each child with a fresh kernel process snapshot before arming.
func verifyV3Observation(encoded string, authority v3Authority, now time.Time) (v3Observation, error) {
	var result v3Observation
	f := authority.FD3
	a := authority.Assignment
	if a == nil {
		return result, invalid
	}
	o, envelope, err := signedV3Payload(encoded, authority.Pin[:], v3ObservationPurpose)
	if err != nil || !exactKeys(o, "contract", "kind", "schema_version", "profile_in_force",
		"host_id", "installation_id", "soul_id", "start_id", "hq_epoch",
		"reservation_sha256", "assignment_envelope_sha256", "provisional_hq_mapping_sha256",
		"provisional_hq_mapping", "members", "observed_at", "issued_at", "expires_at") ||
		field(o, "contract") != "machine/v3" ||
		field(o, "kind") != "stage2a-member-set-child-observation" ||
		integer(o, "schema_version") != 1 ||
		field(o, "profile_in_force") != "managed-protected" {
		return v3Observation{}, invalid
	}
	for _, key := range []string{"profile_in_force", "host_id", "installation_id",
		"soul_id", "start_id", "hq_epoch", "reservation_sha256"} {
		if field(o, key) == "" || field(o, key) != field(a, key) {
			return v3Observation{}, invalid
		}
	}
	if field(o, "assignment_envelope_sha256") != f.Selectors.AssignmentDigest {
		return v3Observation{}, invalid
	}
	expires, err := time.Parse(time.RFC3339Nano, field(o, "expires_at"))
	issued, issuedErr := time.Parse(time.RFC3339Nano, field(o, "issued_at"))
	observed, observedErr := time.Parse(time.RFC3339Nano, field(o, "observed_at"))
	if err != nil || issuedErr != nil || observedErr != nil ||
		!now.Before(expires) || !now.Before(f.Expires) ||
		issued.After(now) || observed.After(issued) || !observed.Before(expires) {
		return v3Observation{}, invalid
	}
	mapping, ok := object(o["provisional_hq_mapping"])
	if !ok || !exactKeys(mapping, "contract", "kind", "schema_version",
		"profile_in_force", "host_id", "installation_id", "soul_id", "start_id",
		"hq_epoch", "assignment_envelope_sha256", "runtime_state", "acp_authority",
		"members", "issued_at", "expires_at") ||
		field(mapping, "contract") != "hq/v1" ||
		field(mapping, "kind") != "stage2a-provisional-member-map" ||
		integer(mapping, "schema_version") != 1 ||
		field(mapping, "runtime_state") != "provisional" ||
		field(mapping, "acp_authority") != "withheld" ||
		field(mapping, "assignment_envelope_sha256") != f.Selectors.AssignmentDigest {
		return v3Observation{}, invalid
	}
	for _, key := range []string{"profile_in_force", "host_id", "installation_id",
		"soul_id", "start_id", "hq_epoch"} {
		if field(mapping, key) == "" || field(mapping, key) != field(o, key) {
			return v3Observation{}, invalid
		}
	}
	mapExpiry, err := time.Parse(time.RFC3339Nano, field(mapping, "expires_at"))
	mapIssued, issuedErr := time.Parse(time.RFC3339Nano, field(mapping, "issued_at"))
	mapBytes, mapErr := canonicalBytes(mapping)
	if err != nil || issuedErr != nil || mapErr != nil ||
		!now.Before(mapExpiry) ||
		mapIssued.After(observed) || mapIssued.After(now) ||
		digest(mapBytes) != field(o, "provisional_hq_mapping_sha256") {
		return v3Observation{}, invalid
	}
	children, ok := array(o["members"])
	mapped, mapOK := array(mapping["members"])
	if !ok || !mapOK || len(children) != 2 || len(mapped) != 2 {
		return v3Observation{}, invalid
	}
	firstBinding := ""
	for i := 0; i < 2; i++ {
		child, childOK := object(children[i])
		mapMember, memberOK := object(mapped[i])
		if !childOK || !memberOK ||
			!exactKeys(child, "member_id", "launch_id", "member_selector", "runtime_id", "child_process") ||
			!exactKeys(mapMember, "member_id", "member_selector", "runtime_id", "channel_binding") ||
			field(child, "member_id") != authority.Members[i].ID ||
			field(child, "launch_id") != authority.Members[i].Launch ||
			field(child, "member_selector") != authority.Members[i].Selector ||
			field(mapMember, "member_id") != authority.Members[i].ID ||
			field(mapMember, "member_selector") != authority.Members[i].Selector ||
			field(mapMember, "runtime_id") != field(child, "runtime_id") ||
			!idPattern.MatchString(field(child, "runtime_id")) ||
			field(mapMember, "channel_binding") == "" {
			return v3Observation{}, invalid
		}
		process, ok := object(child["child_process"])
		if !ok || !exactKeys(process, "pid", "uid", "gid", "parent_pid",
			"process_group_id", "start_seconds", "start_micros", "executable_sha256") ||
			integer(process, "pid") < 2 ||
			integer(process, "uid") < 300 || integer(process, "uid") > 399 ||
			integer(process, "gid") < 1 || integer(process, "parent_pid") < 2 ||
			integer(process, "process_group_id") < 2 ||
			integer(process, "start_seconds") < 1 ||
			integer(process, "start_micros") < 0 ||
			integer(process, "start_micros") >= 1000000 ||
			field(process, "executable_sha256") != authority.Members[i].CommandDigest {
			return v3Observation{}, invalid
		}
		if i == 1 && (integer(process, "pid") == result.Children[0].PID ||
			field(child, "runtime_id") == result.Children[0].RuntimeID ||
			field(mapMember, "channel_binding") == firstBinding) {
			return v3Observation{}, invalid
		}
		if i == 0 {
			firstBinding = field(mapMember, "channel_binding")
		}
		result.Children[i] = v3ObservedChild{
			MemberID: authority.Members[i].ID, Selector: authority.Members[i].Selector,
			Launch: authority.Members[i].Launch, RuntimeID: field(child, "runtime_id"),
			PID: integer(process, "pid"), UID: uint32(integer(process, "uid")),
			GID: uint32(integer(process, "gid")), ParentPID: integer(process, "parent_pid"),
			ProcessGroup:  integer(process, "process_group_id"),
			StartSeconds:  integer(process, "start_seconds"),
			StartMicros:   integer(process, "start_micros"),
			CommandDigest: field(process, "executable_sha256"),
		}
	}
	result.EnvelopeDigest = digest(envelope)
	result.MapDigest = digest(mapBytes)
	result.Expires = expires
	return result, nil
}

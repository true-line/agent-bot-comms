package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strconv"
	"time"
)

const (
	observedFD3Version         = "stage2a-b-observed-body-local-test-assignment/v1"
	observedAssignmentPurpose  = "agent-bot/stage2a-member-set-assignment-local-test/v1"
	observedAuthorityPurpose   = "agent-bot/stage2a-b-member-authority-local-test/v1"
	observedReservationPurpose = "agent-bot/stage2a-observed-body-local-test-reservation/v1"
)

type observedFD3 struct {
	Version            string            `json:"version"`
	MachinePinPath     string            `json:"machine_pin_path"`
	AssignmentEnvelope string            `json:"assignment_envelope_base64url"`
	AuthorityEnvelope  string            `json:"authority_envelope_base64url"`
	Selectors          observedSelectors `json:"selectors"`
	Epoch              string            `json:"hq_epoch"`
	BridgeUID          uint32            `json:"bridge_uid"`
	HQUID              uint32            `json:"hq_uid"`
	RunnerUID          uint32            `json:"runner_uid"`
	Expires            time.Time         `json:"expires_at"`
	Broker             endpoint          `json:"broker"`
	Relay              endpoint          `json:"relay"`
	LocalTest          observedLocalTest `json:"local_test"`
}

type observedAuthority struct {
	FD3                observedFD3
	ResponseTextSHA256 string
	SelectedCommandSHA string
	SelectedCLISHA     string
	Pin                [32]byte
}

func observedSameTyped(value any, typed any) bool {
	actual, err1 := canonicalBytes(value)
	want, err2 := canonicalJSONValue(typed)
	return err1 == nil && err2 == nil && bytes.Equal(actual, want)
}

// No v2 or cooperative fallback is available for this FD3 version. The
// independently opened Machine pin is supplied by entry only after its fixed
// path has been reopened; neither FD3 envelope supplies a trust root.
func verifyObservedFD3(raw, pin []byte, now time.Time) (observedAuthority, error) {
	var f observedFD3
	var empty observedAuthority
	if len(raw) == 0 || len(raw) > cooperativeFD3MaxBytes ||
		decode(raw, &f) != nil || len(pin) != 32 ||
		f.Version != observedFD3Version || f.MachinePinPath != v3PinPath ||
		f.Selectors.validate() != nil || !now.Before(f.Expires) ||
		!hexPattern.MatchString(f.Epoch) ||
		f.BridgeUID < 300 || f.BridgeUID > 399 ||
		f.HQUID < 300 || f.HQUID > 399 ||
		f.RunnerUID < 300 || f.RunnerUID > 399 ||
		f.BridgeUID == f.HQUID || f.BridgeUID == f.RunnerUID ||
		f.HQUID == f.RunnerUID ||
		!validV3Endpoint(f.Broker, f.HQUID, f.BridgeUID, true) ||
		!validV3Endpoint(f.Relay, f.BridgeUID, f.RunnerUID, false) ||
		f.Broker.Path == f.Relay.Path ||
		filepath.Dir(f.Broker.Path) == filepath.Dir(f.Relay.Path) ||
		f.LocalTest.validate(f.Selectors.InstallationID, f.Selectors.StartID) != nil {
		return empty, invalid
	}
	s := f.Selectors
	a, assignmentBytes, err := signedV3Payload(f.AssignmentEnvelope, pin, observedAssignmentPurpose)
	if err != nil || digest(assignmentBytes) != s.AssignmentEnvelopeSHA {
		return empty, invalid
	}
	b, authorityBytes, err := signedV3Payload(f.AuthorityEnvelope, pin, observedAuthorityPurpose)
	if err != nil || digest(authorityBytes) != s.AuthorityEnvelopeSHA {
		return empty, invalid
	}
	if !exactKeys(a, "contract", "kind", "schema_version", "profile_in_force", "host_id",
		"installation_id", "soul_id", "start_id", "hq_epoch", "plan_id", "plan_digest",
		"owner_plan_member_set_sha256", "reservation_sha256", "b_authority",
		"soul_artifact_sha256", "frozen_soul_info_sha256", "adapter_manifest_relpath",
		"frozen_adapter_manifest_sha256", "host_projection_sha256", "definition_measurement",
		"runner_uid", "runner_gid", "bridge", "members", "issued_at", "expires_at") ||
		!exactKeys(b, "contract", "kind", "schema_version", "profile_in_force", "host_id",
			"installation_id", "soul_id", "start_id", "hq_epoch", "plan_id", "plan_digest",
			"reservation_sha256", "outer_launch_id", "member_set_assignment_envelope_sha256",
			"owner_plan_member_set_sha256", "b_authority", "hq_uid", "runner_uid",
			"bridge", "members", "local_test", "issued_at", "expires_at") ||
		field(a, "contract") != "machine/local-test-v1" ||
		field(b, "contract") != "machine/local-test-v1" ||
		field(a, "kind") != "stage2a-member-set-assignment" ||
		field(b, "kind") != "stage2a-b-member-authority" ||
		integer(a, "schema_version") != 1 || integer(b, "schema_version") != 1 ||
		field(a, "profile_in_force") != "managed-protected" ||
		field(b, "profile_in_force") != "managed-protected" ||
		!observedSameTyped(b["local_test"], f.LocalTest) {
		return empty, invalid
	}
	for _, key := range []string{"host_id", "installation_id", "soul_id", "start_id",
		"hq_epoch", "plan_id", "plan_digest", "reservation_sha256",
		"owner_plan_member_set_sha256"} {
		if field(a, key) == "" || field(a, key) != field(b, key) {
			return empty, invalid
		}
	}
	if field(a, "installation_id") != s.InstallationID ||
		field(a, "start_id") != s.StartID || field(a, "plan_id") != s.PlanID ||
		field(a, "plan_digest") != s.PlanDigest ||
		field(a, "reservation_sha256") != s.ReservationDigest ||
		field(a, "hq_epoch") != f.Epoch ||
		field(b, "outer_launch_id") != s.LaunchID ||
		field(b, "member_set_assignment_envelope_sha256") != s.AssignmentEnvelopeSHA ||
		integer(a, "runner_uid") != int64(f.RunnerUID) ||
		integer(a, "runner_gid") != int64(f.Relay.Parent.GID) ||
		integer(b, "runner_uid") != int64(f.RunnerUID) ||
		integer(b, "hq_uid") != int64(f.HQUID) {
		return empty, invalid
	}
	ba, okay := object(a["b_authority"])
	bb, okayB := object(b["b_authority"])
	if !okay || !okayB || !exactKeys(ba, "purpose", "envelope_sha256") ||
		!sameValue(ba, bb) || field(ba, "purpose") != observedReservationPurpose ||
		field(ba, "envelope_sha256") != s.ReservationDigest {
		return empty, invalid
	}
	bridgeA, okay := object(a["bridge"])
	bridgeB, okayB := object(b["bridge"])
	endpoints, endpointsOK := object(bridgeA["endpoints"])
	if !okay || !okayB || !endpointsOK ||
		!exactKeys(bridgeA, "account", "uid", "gid", "endpoints") ||
		!exactKeys(endpoints, "broker", "member", "relay") ||
		!sameValue(bridgeA, bridgeB) ||
		integer(bridgeA, "uid") != int64(f.BridgeUID) ||
		integer(bridgeA, "gid") != int64(f.BridgeUID) ||
		!approvedEndpoint(bridgeA, "broker", f.Broker, f.HQUID, f.BridgeUID, f.BridgeUID) ||
		!approvedEndpoint(bridgeA, "relay", f.Relay, f.BridgeUID, f.RunnerUID, f.RunnerUID) {
		return empty, invalid
	}
	memberEndpoint, okay := object(endpoints["member"])
	memberPeers, peersOK := array(memberEndpoint["peer_uids"])
	if !okay || !exactKeys(memberEndpoint, "directory", "socket_path", "owner_uid",
		"group_gid", "dir_mode", "socket_mode", "peer_uids") ||
		!filepath.IsAbs(field(memberEndpoint, "socket_path")) ||
		filepath.Clean(field(memberEndpoint, "socket_path")) != field(memberEndpoint, "socket_path") ||
		filepath.Dir(field(memberEndpoint, "socket_path")) != field(memberEndpoint, "directory") ||
		integer(memberEndpoint, "owner_uid") != int64(f.RunnerUID) ||
		integer(memberEndpoint, "group_gid") != int64(f.BridgeUID) ||
		integer(memberEndpoint, "dir_mode") != 02750 ||
		integer(memberEndpoint, "socket_mode") != 0660 ||
		!peersOK || len(memberPeers) != 2 ||
		!sameValue(memberPeers, []any{json.Number(strconv.FormatUint(uint64(f.RunnerUID), 10)),
			json.Number(strconv.FormatUint(uint64(f.BridgeUID), 10))}) {
		return empty, invalid
	}
	assigned, okay := array(a["members"])
	authorized, okayB := array(b["members"])
	if !okay || !okayB || len(assigned) != 2 || len(authorized) != 2 {
		return empty, invalid
	}
	selectors := make([]any, 2)
	projection := make([]any, 2)
	leads, selected := 0, 0
	for i := 0; i < 2; i++ {
		am, okay := object(assigned[i])
		bm, okayB := object(authorized[i])
		if !okay || !okayB ||
			!exactKeys(am, "member_id", "role", "adapter_id", "adapter_version",
				"command_path", "command_sha256", "adjacent_cli_path", "adjacent_cli_sha256",
				"launch_id", "member_selector") ||
			!exactKeys(bm, "member_id", "launch_id", "member_selector",
				"adjacent_cli_path", "adjacent_cli_sha256", "qualification") {
			return empty, invalid
		}
		id, launch, selector := field(am, "member_id"), field(am, "launch_id"), field(am, "member_selector")
		if !idPattern.MatchString(id) || !launchPattern.MatchString(launch) ||
			!selectorPattern.MatchString(selector) ||
			(field(am, "role") != "lead" && field(am, "role") != "specialist") ||
			!idPattern.MatchString(field(am, "adapter_id")) ||
			field(am, "adapter_version") == "" ||
			!validDigest(field(am, "command_sha256")) ||
			!validDigest(field(am, "adjacent_cli_sha256")) ||
			!filepath.IsAbs(field(am, "command_path")) ||
			!filepath.IsAbs(field(am, "adjacent_cli_path")) ||
			filepath.Dir(field(am, "command_path")) != filepath.Dir(field(am, "adjacent_cli_path")) ||
			field(bm, "member_id") != id || field(bm, "launch_id") != launch ||
			field(bm, "member_selector") != selector ||
			field(bm, "adjacent_cli_path") != field(am, "adjacent_cli_path") ||
			field(bm, "adjacent_cli_sha256") != field(am, "adjacent_cli_sha256") ||
			(i == 1 && (id <= field(assigned[0].(map[string]any), "member_id") ||
				launch == field(assigned[0].(map[string]any), "launch_id") ||
				selector == field(assigned[0].(map[string]any), "member_selector"))) {
			return empty, invalid
		}
		selectorHash := sha256.Sum256([]byte(v3SelectorPurpose + "\x00" + s.ReservationDigest +
			"\x00" + id + "\x00" + launch))
		if selector != "mb_"+hex.EncodeToString(selectorHash[:]) {
			return empty, invalid
		}
		if field(am, "role") == "lead" {
			leads++
		}
		q, okay := object(bm["qualification"])
		if !okay {
			return empty, invalid
		}
		if id == f.LocalTest.SelectedMemberID {
			selected++
			if field(am, "role") != "lead" || launch != f.LocalTest.SelectedLaunchID ||
				selector != f.LocalTest.SelectedMemberSelector ||
				!exactKeys(q, "mode", "model", "body_profile", "static_projection_sha256",
					"owner_prompt_sha256", "r_first_brief_sha256", "header_shape_sha256",
					"client_key_sha256", "http_host", "messages_query", "response_text_sha256") ||
				field(q, "mode") != "observed-body-local-test/v1" ||
				field(q, "model") != f.LocalTest.Model ||
				field(q, "body_profile") != f.LocalTest.BodyProfile ||
				field(q, "static_projection_sha256") != f.LocalTest.StaticProjectionSHA256 ||
				field(q, "owner_prompt_sha256") != f.LocalTest.OwnerPromptSHA256 ||
				field(q, "r_first_brief_sha256") != f.LocalTest.FirstBriefSHA256 ||
				field(q, "header_shape_sha256") != f.LocalTest.HeaderShapeSHA256 ||
				field(q, "client_key_sha256") != f.LocalTest.ClientKeySHA256 ||
				field(q, "http_host") != f.LocalTest.HTTPHost ||
				field(q, "messages_query") != f.LocalTest.MessagesQuery ||
				!validDigest(field(q, "response_text_sha256")) {
				return empty, invalid
			}
			empty.ResponseTextSHA256 = field(q, "response_text_sha256")
			empty.SelectedCommandSHA = field(am, "command_sha256")
			empty.SelectedCLISHA = field(am, "adjacent_cli_sha256")
		} else if !exactKeys(q, "mode") || field(q, "mode") != "disabled" {
			return empty, invalid
		}
		selectors[i] = selector
		projection[i] = map[string]any{"member_id": id, "role": field(am, "role"),
			"adapter_id": field(am, "adapter_id"), "adapter_version": field(am, "adapter_version"),
			"command_path": field(am, "command_path"), "command_sha256": field(am, "command_sha256"),
			"adjacent_cli_path":   field(am, "adjacent_cli_path"),
			"adjacent_cli_sha256": field(am, "adjacent_cli_sha256")}
	}
	if leads != 1 || selected != 1 {
		return observedAuthority{}, invalid
	}
	selectorBytes, err := canonicalBytes(selectors)
	if err != nil || digest(selectorBytes) != s.MemberSelectorsSHA256 {
		return observedAuthority{}, invalid
	}
	projectionBytes, err := canonicalBytes(projection)
	if err != nil || digest(projectionBytes) != field(a, "owner_plan_member_set_sha256") {
		return observedAuthority{}, invalid
	}
	issuedA, e1 := time.Parse(time.RFC3339Nano, field(a, "issued_at"))
	issuedB, e2 := time.Parse(time.RFC3339Nano, field(b, "issued_at"))
	expiresA, e3 := time.Parse(time.RFC3339Nano, field(a, "expires_at"))
	expiresB, e4 := time.Parse(time.RFC3339Nano, field(b, "expires_at"))
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || now.Before(issuedA) ||
		now.Before(issuedB) || !now.Before(expiresA) || !now.Before(expiresB) ||
		f.Expires.After(expiresA) || f.Expires.After(expiresB) {
		return observedAuthority{}, invalid
	}
	empty.FD3 = f
	copy(empty.Pin[:], pin)
	return empty, nil
}

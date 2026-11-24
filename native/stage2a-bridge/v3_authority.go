package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	v3Version           = "stage2a-b-assignment/v3"
	v3AssignmentPurpose = "agent-bot/stage2a-member-set-assignment/v1"
	v3AuthorityPurpose  = "agent-bot/stage2a-b-member-authority/v1"
	v3PinPath           = "/Library/Application Support/ai.true-line.agent-bot-hq/soul-authority.pub"
	v3SelectorPurpose   = "agent-bot/stage2a-member-selector/v1"
)

var selectorPattern = regexp.MustCompile(`^mb_[0-9a-f]{64}$`)

type v3Selectors struct {
	Installation          string `json:"installation_id"`
	Start                 string `json:"start_id"`
	Plan                  string `json:"plan_id"`
	PlanDigest            string `json:"plan_digest"`
	Reservation           string `json:"reservation_digest"`
	AssignmentDigest      string `json:"assignment_envelope_sha256"`
	AuthorityDigest       string `json:"authority_envelope_sha256"`
	MemberSelectorsDigest string `json:"member_selectors_sha256"`
}

type v3FD3 struct {
	Version            string      `json:"version"`
	MachinePinPath     string      `json:"machine_pin_path"`
	AssignmentEnvelope string      `json:"assignment_envelope_base64url"`
	AuthorityEnvelope  string      `json:"authority_envelope_base64url"`
	Selectors          v3Selectors `json:"selectors"`
	Epoch              string      `json:"hq_epoch"`
	BridgeUID          uint32      `json:"bridge_uid"`
	HQUID              uint32      `json:"hq_uid"`
	RunnerUID          uint32      `json:"runner_uid"`
	Expires            time.Time   `json:"expires_at"`
	Broker             endpoint    `json:"broker"`
	Relay              endpoint    `json:"relay"`
}

type v3Member struct {
	ID            string
	Launch        string
	Selector      string
	CLIPath       string
	CLIDigest     string
	CommandPath   string
	CommandDigest string
	Policy        assignment
	ResponseText  string
}

type v3Authority struct {
	FD3        v3FD3
	Members    [2]v3Member
	Assignment map[string]any
	Pin        [32]byte
}

func object(value any) (map[string]any, bool)    { m, ok := value.(map[string]any); return m, ok }
func array(value any) ([]any, bool)              { a, ok := value.([]any); return a, ok }
func field(m map[string]any, name string) string { s, _ := m[name].(string); return s }
func integer(m map[string]any, name string) int64 {
	n, ok := m[name].(json.Number)
	if !ok {
		return -1
	}
	v, err := n.Int64()
	if err != nil {
		return -1
	}
	return v
}
func exactKeys(m map[string]any, keys ...string) bool {
	if len(m) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := m[key]; !ok {
			return false
		}
	}
	return true
}
func canonicalBytes(value any) ([]byte, error) {
	var out bytes.Buffer
	if jcsValue(value, &out) != nil {
		return nil, invalid
	}
	return out.Bytes(), nil
}
func sameValue(a, b any) bool {
	x, e1 := canonicalBytes(a)
	y, e2 := canonicalBytes(b)
	return e1 == nil && e2 == nil && bytes.Equal(x, y)
}
func unpadded(value string, max int) ([]byte, error) {
	if len(value) == 0 || len(value) > max*2 || strings.ContainsAny(value, "=+/\r\n") {
		return nil, invalid
	}
	b, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(b) == 0 || len(b) > max || base64.RawURLEncoding.EncodeToString(b) != value {
		return nil, invalid
	}
	return b, nil
}
func signedV3Payload(encoded string, pin []byte, purpose string) (map[string]any, []byte, error) {
	if len(pin) != ed25519.PublicKeySize {
		return nil, nil, invalid
	}
	envelopeBytes, err := unpadded(encoded, 16384)
	if err != nil {
		return nil, nil, invalid
	}
	envelope, err := canonicalSignedJSON(envelopeBytes)
	if err != nil || !exactKeys(envelope, "schema_version", "purpose", "issuer_public_key_base64url", "payload_sha256", "payload_base64url", "signature_base64url") ||
		integer(envelope, "schema_version") != 1 || field(envelope, "purpose") != purpose {
		return nil, nil, invalid
	}
	issuer, err := unpadded(field(envelope, "issuer_public_key_base64url"), 32)
	if err != nil || !bytes.Equal(issuer, pin) {
		return nil, nil, invalid
	}
	payloadBytes, err := unpadded(field(envelope, "payload_base64url"), 16384)
	if err != nil || digest(payloadBytes) != field(envelope, "payload_sha256") {
		return nil, nil, invalid
	}
	signature, err := unpadded(field(envelope, "signature_base64url"), 64)
	if err != nil || len(signature) != 64 || !ed25519.Verify(pin,
		append([]byte(purpose+"\x00"), payloadBytes...), signature) {
		return nil, nil, invalid
	}
	payload, err := canonicalSignedJSON(payloadBytes)
	if err != nil {
		return nil, nil, invalid
	}
	return payload, envelopeBytes, nil
}

func validV3Endpoint(e endpoint, owner, group uint32, created bool) bool {
	return filepath.IsAbs(e.Path) && filepath.Clean(e.Path) == e.Path && len(e.Path) <= 103 &&
		!strings.ContainsAny(e.Path, "\x00\r\n") && e.Parent.UID == owner && e.Parent.GID == group &&
		e.Parent.Mode == 02750 && e.Parent.Inode != 0 && e.Socket.UID == owner &&
		e.Socket.GID == group && e.Socket.Mode == 0660 &&
		((created && e.Socket.Inode != 0) || (!created && e.Socket.Inode == 0 && e.Socket.Device == 0))
}

func approvedEndpoint(bridge map[string]any, kind string, e endpoint, owner, group uint32, peers ...uint32) bool {
	endpoints, ok := object(bridge["endpoints"])
	if !ok {
		return false
	}
	approved, ok := object(endpoints[kind])
	if !ok || !exactKeys(approved, "directory", "socket_path", "owner_uid", "group_gid", "dir_mode", "socket_mode", "peer_uids") {
		return false
	}
	listed, ok := array(approved["peer_uids"])
	if !ok || len(listed) != len(peers) {
		return false
	}
	for i, peer := range peers {
		n, ok := listed[i].(json.Number)
		if !ok || string(n) != strconv.FormatUint(uint64(peer), 10) {
			return false
		}
	}
	return field(approved, "directory") == filepath.Dir(e.Path) && field(approved, "socket_path") == e.Path &&
		integer(approved, "owner_uid") == int64(owner) && integer(approved, "group_gid") == int64(group) &&
		integer(approved, "dir_mode") == 02750 && integer(approved, "socket_mode") == 0660
}

// This accepts only the protected v3 producer currently present in Machine.
// The cooperative v3 producer must be independently reviewed before B can
// accept that profile. FD3 does not trust its own issuer: the installed pin
// is opened separately by the native entry point before calling this parser.
func verifyV3FD3(raw, pin []byte, now time.Time) (v3Authority, error) {
	var frame v3FD3
	if len(raw) == 0 || len(raw) > 16384 || decode(raw, &frame) != nil {
		return v3Authority{}, invalid
	}
	return verifyMemberPolicy(frame, pin, now, nil)
}

// Cooperative B receives the same two-member policy only after its distinct
// FD3 HMAC bind. The common member projection checks remain shared; the
// profile, reservation purpose and endpoint records are mode-specific.
func verifyMemberPolicy(f v3FD3, pin []byte, now time.Time,
	cooperative *cooperativeBridgeAuthority) (v3Authority, error) {
	result := v3Authority{FD3: f}
	s := f.Selectors
	uidOK := func(u uint32) bool { return u >= 300 && u <= 399 }
	if f.Version != v3Version || f.MachinePinPath != v3PinPath || !now.Before(f.Expires) ||
		!uidOK(f.BridgeUID) || !uidOK(f.HQUID) || !uidOK(f.RunnerUID) ||
		f.BridgeUID == f.HQUID || f.BridgeUID == f.RunnerUID || f.HQUID == f.RunnerUID ||
		!idPattern.MatchString(s.Installation) || !startPattern.MatchString(s.Start) ||
		!idPattern.MatchString(s.Plan) || !hexPattern.MatchString(s.PlanDigest) ||
		!validDigest(s.Reservation) || !validDigest(s.AssignmentDigest) ||
		!validDigest(s.AuthorityDigest) || !validDigest(s.MemberSelectorsDigest) ||
		!hexPattern.MatchString(f.Epoch) || !validV3Endpoint(f.Broker, f.HQUID, f.BridgeUID, true) ||
		!validV3Endpoint(f.Relay, f.BridgeUID, f.RunnerUID, false) ||
		f.Broker.Path == f.Relay.Path || filepath.Dir(f.Broker.Path) == filepath.Dir(f.Relay.Path) {
		return v3Authority{}, invalid
	}
	a, ab, err := signedV3Payload(f.AssignmentEnvelope, pin, v3AssignmentPurpose)
	if err != nil || digest(ab) != s.AssignmentDigest {
		return v3Authority{}, invalid
	}
	copy(result.Pin[:], pin)
	result.Assignment = a
	b, bb, err := signedV3Payload(f.AuthorityEnvelope, pin, v3AuthorityPurpose)
	if err != nil || digest(bb) != s.AuthorityDigest {
		return v3Authority{}, invalid
	}
	if !exactKeys(a, "contract", "kind", "schema_version", "profile_in_force", "host_id",
		"installation_id", "soul_id", "start_id", "hq_epoch", "plan_id", "plan_digest",
		"owner_plan_member_set_sha256", "reservation_sha256", "b_authority",
		"soul_artifact_sha256", "frozen_soul_info_sha256", "adapter_manifest_relpath",
		"frozen_adapter_manifest_sha256", "host_projection_sha256", "definition_measurement",
		"runner_uid", "runner_gid", "bridge", "members", "issued_at", "expires_at") ||
		!exactKeys(b, "contract", "kind", "schema_version", "profile_in_force", "host_id",
			"installation_id", "soul_id", "start_id", "hq_epoch", "plan_id", "plan_digest",
			"reservation_sha256", "member_set_assignment_envelope_sha256",
			"owner_plan_member_set_sha256", "b_authority", "hq_uid", "runner_uid",
			"bridge", "members", "issued_at", "expires_at") {
		return v3Authority{}, invalid
	}
	profile := "managed-protected"
	if cooperative != nil {
		profile = "managed-cooperative"
	}
	if field(a, "contract") != "machine/v3" || field(a, "kind") != "stage2a-member-set-assignment" ||
		field(b, "contract") != "machine/v3" || field(b, "kind") != "stage2a-b-member-authority" ||
		integer(a, "schema_version") != 1 || integer(b, "schema_version") != 1 ||
		field(a, "profile_in_force") != profile || field(b, "profile_in_force") != profile {
		return v3Authority{}, invalid
	}
	for _, key := range []string{"host_id", "installation_id", "soul_id", "start_id", "hq_epoch", "plan_id", "plan_digest", "reservation_sha256", "owner_plan_member_set_sha256"} {
		if field(a, key) == "" || field(a, key) != field(b, key) {
			return v3Authority{}, invalid
		}
	}
	if field(a, "installation_id") != s.Installation || field(a, "start_id") != s.Start ||
		field(a, "plan_id") != s.Plan || field(a, "plan_digest") != s.PlanDigest ||
		field(a, "reservation_sha256") != s.Reservation || field(a, "hq_epoch") != f.Epoch ||
		field(b, "member_set_assignment_envelope_sha256") != s.AssignmentDigest ||
		integer(a, "runner_uid") != int64(f.RunnerUID) ||
		integer(a, "runner_gid") != int64(f.Relay.Parent.GID) ||
		integer(b, "runner_uid") != int64(f.RunnerUID) ||
		integer(b, "hq_uid") != int64(f.HQUID) {
		return v3Authority{}, invalid
	}
	ba, okA := object(a["b_authority"])
	bbAuth, okB := object(b["b_authority"])
	wantPurpose, wantDigest := "agent-bot/stage2a-reservation/v3", s.Reservation
	if cooperative != nil {
		wantPurpose, wantDigest = cooperativeBridgePurpose, cooperative.AssignmentSHA
	}
	if !okA || !okB || !exactKeys(ba, "purpose", "envelope_sha256") || !sameValue(ba, bbAuth) ||
		field(ba, "purpose") != wantPurpose || field(ba, "envelope_sha256") != wantDigest {
		return v3Authority{}, invalid
	}
	bridgeA, okA := object(a["bridge"])
	bridgeB, okB := object(b["bridge"])
	endpoints, endpointsOK := object(bridgeA["endpoints"])
	if !okA || !okB || !endpointsOK || !exactKeys(bridgeA, "account", "uid", "gid", "endpoints") ||
		!exactKeys(endpoints, "broker", "member", "relay") || !sameValue(bridgeA, bridgeB) ||
		integer(bridgeA, "uid") != int64(f.BridgeUID) || integer(bridgeA, "gid") != int64(f.BridgeUID) {
		return v3Authority{}, invalid
	}
	if cooperative == nil {
		if !approvedEndpoint(bridgeA, "broker", f.Broker, f.HQUID, f.BridgeUID, f.BridgeUID) ||
			!approvedEndpoint(bridgeA, "relay", f.Relay, f.BridgeUID, f.RunnerUID, f.RunnerUID) {
			return v3Authority{}, invalid
		}
	} else if !sameValue(endpoints["broker"], cooperative.BrokerRecord) ||
		!sameValue(endpoints["member"], cooperative.MemberRecord) ||
		!sameValue(endpoints["relay"], cooperative.RelayRecord) ||
		!cooperativeEndpointIdentityMatches(cooperative.BrokerRecord, f.Broker, true) ||
		!cooperativeEndpointIdentityMatches(cooperative.RelayRecord, f.Relay, false) {
		return v3Authority{}, invalid
	}
	memberEndpoint, memberOK := object(endpoints["member"])
	if !memberOK ||
		!filepath.IsAbs(field(memberEndpoint, "socket_path")) ||
		filepath.Clean(field(memberEndpoint, "socket_path")) != field(memberEndpoint, "socket_path") ||
		filepath.Dir(field(memberEndpoint, "socket_path")) != field(memberEndpoint, "directory") ||
		len(field(memberEndpoint, "socket_path")) > 103 ||
		integer(memberEndpoint, "owner_uid") != int64(f.RunnerUID) ||
		integer(memberEndpoint, "group_gid") != int64(f.BridgeUID) ||
		integer(memberEndpoint, "dir_mode") != 02750 || integer(memberEndpoint, "socket_mode") != 0660 {
		return v3Authority{}, invalid
	}
	if cooperative == nil {
		memberPeers, peersOK := array(memberEndpoint["peer_uids"])
		if !exactKeys(memberEndpoint, "directory", "socket_path", "owner_uid", "group_gid", "dir_mode", "socket_mode", "peer_uids") ||
			!peersOK || len(memberPeers) != 2 || !sameValue(memberPeers, []any{
			json.Number(strconv.FormatUint(uint64(f.RunnerUID), 10)),
			json.Number(strconv.FormatUint(uint64(f.BridgeUID), 10)),
		}) {
			return v3Authority{}, invalid
		}
	} else if !sameValue(memberEndpoint, cooperative.MemberRecord) ||
		integer(memberEndpoint, "expected_peer_uid") != int64(f.BridgeUID) {
		return v3Authority{}, invalid
	}
	assignMembers, okA := array(a["members"])
	authorityMembers, okB := array(b["members"])
	if !okA || !okB || len(assignMembers) != 2 || len(authorityMembers) != 2 {
		return v3Authority{}, invalid
	}
	selectors := make([]any, 2)
	projection := make([]any, 2)
	leads := 0
	for i := 0; i < 2; i++ {
		am, okay := object(assignMembers[i])
		bm, okb := object(authorityMembers[i])
		if !okay || !okb || !exactKeys(am, "member_id", "role", "adapter_id", "adapter_version", "command_path", "command_sha256", "adjacent_cli_path", "adjacent_cli_sha256", "launch_id", "member_selector") ||
			!exactKeys(bm, "member_id", "launch_id", "member_selector", "adjacent_cli_path", "adjacent_cli_sha256", "qualification") {
			return v3Authority{}, invalid
		}
		id, launch, selector := field(am, "member_id"), field(am, "launch_id"), field(am, "member_selector")
		if !idPattern.MatchString(id) || !launchPattern.MatchString(launch) || !selectorPattern.MatchString(selector) ||
			(field(am, "role") != "lead" && field(am, "role") != "specialist") || !idPattern.MatchString(field(am, "adapter_id")) ||
			field(am, "adapter_version") == "" || !validDigest(field(am, "command_sha256")) ||
			!validDigest(field(am, "adjacent_cli_sha256")) ||
			!filepath.IsAbs(field(am, "command_path")) || !filepath.IsAbs(field(am, "adjacent_cli_path")) ||
			filepath.Dir(field(am, "command_path")) != filepath.Dir(field(am, "adjacent_cli_path")) ||
			field(bm, "member_id") != id || field(bm, "launch_id") != launch ||
			field(bm, "member_selector") != selector ||
			field(bm, "adjacent_cli_path") != field(am, "adjacent_cli_path") ||
			field(bm, "adjacent_cli_sha256") != field(am, "adjacent_cli_sha256") {
			return v3Authority{}, invalid
		}
		selectorHash := sha256.Sum256([]byte(v3SelectorPurpose + "\x00" + s.Reservation + "\x00" + id + "\x00" + launch))
		if selector != "mb_"+hex.EncodeToString(selectorHash[:]) {
			return v3Authority{}, invalid
		}
		if field(am, "role") == "lead" {
			leads++
		}
		if i == 1 && (id <= result.Members[0].ID || launch == result.Members[0].Launch || selector == result.Members[0].Selector) {
			return v3Authority{}, invalid
		}
		q, ok := object(bm["qualification"])
		responseText, responseIsString := q["response_text"].(string)
		if !ok || !exactKeys(q, "model", "request_sha256", "headers_sha256", "client_key_sha256", "http_host", "messages_query", "response_text") ||
			!idPattern.MatchString(field(q, "model")) || !idPattern.MatchString(field(q, "http_host")) ||
			!queryPattern.MatchString(field(q, "messages_query")) ||
			!validDigest(field(q, "request_sha256")) || !validDigest(field(q, "headers_sha256")) ||
			!validDigest(field(q, "client_key_sha256")) || !responseIsString || len(responseText) > 2048 {
			return v3Authority{}, invalid
		}
		result.Members[i] = v3Member{ID: id, Launch: launch, Selector: selector,
			CLIPath: field(am, "adjacent_cli_path"), CLIDigest: field(am, "adjacent_cli_sha256"),
			CommandPath:   field(am, "command_path"),
			CommandDigest: field(am, "command_sha256"),
			ResponseText:  responseText,
			Policy: assignment{Model: field(q, "model"), RequestDigest: field(q, "request_sha256"),
				HeadersDigest: field(q, "headers_sha256"), ClientKeyDigest: field(q, "client_key_sha256"),
				HTTPHost: field(q, "http_host"), MessagesQuery: field(q, "messages_query")}}
		selectors[i] = selector
		projection[i] = map[string]any{"member_id": id, "role": field(am, "role"),
			"adapter_id": field(am, "adapter_id"), "adapter_version": field(am, "adapter_version"),
			"command_path": field(am, "command_path"), "command_sha256": field(am, "command_sha256"),
			"adjacent_cli_path": field(am, "adjacent_cli_path"), "adjacent_cli_sha256": field(am, "adjacent_cli_sha256")}
	}
	if leads != 1 {
		return v3Authority{}, invalid
	}
	selectorBytes, err := canonicalBytes(selectors)
	if err != nil || digest(selectorBytes) != s.MemberSelectorsDigest {
		return v3Authority{}, invalid
	}
	projectionBytes, err := canonicalBytes(projection)
	if err != nil || digest(projectionBytes) != field(a, "owner_plan_member_set_sha256") {
		return v3Authority{}, invalid
	}
	assignmentExpires, e1 := time.Parse(time.RFC3339Nano, field(a, "expires_at"))
	authorityExpires, e2 := time.Parse(time.RFC3339Nano, field(b, "expires_at"))
	if e1 != nil || e2 != nil || !now.Before(assignmentExpires) || !now.Before(authorityExpires) ||
		f.Expires.After(assignmentExpires) || f.Expires.After(authorityExpires) {
		return v3Authority{}, invalid
	}
	return result, nil
}

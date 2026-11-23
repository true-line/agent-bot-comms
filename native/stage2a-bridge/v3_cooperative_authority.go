package main

import (
	"bytes"
	"crypto/ed25519"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	cooperativeReservationPurpose = "agent-bot/soul-cooperative-reservation/v3"
	cooperativeBridgePurpose      = "agent-bot/soul-cooperative-bridge-assignment/v3"
	cooperativeStartVersion       = "agent-bot-comms/cooperative-b-start/v3"
	cooperativeFD3MaxBytes        = 32 * 1024
)

type cooperativeFD3 struct {
	Version             string `json:"version"`
	MachinePinPath      string `json:"machine_pin_path"`
	ReservationEnvelope string `json:"reservation_envelope_base64url"`
	BridgeEnvelope      string `json:"bridge_assignment_envelope_base64url"`
}

// This verifies A's cooperative B assignment before a future, separately
// versioned FD3 handoff may use it. It does not open a listener or grant relay
// access. The protected v3 FD3 parser remains a distinct profile gate.
type cooperativeBridgeAuthority struct {
	FD3            cooperativeFD3
	BridgeUID      uint32
	RunnerUID      uint32
	HQUID          uint32
	HostID         string
	SoulID         string
	Installation   string
	Start          string
	Launch         string
	Plan           string
	PlanDigest     string
	Epoch          string
	BrokerPath     string
	MemberPath     string
	RelayPath      string
	BrokerRecord   map[string]any
	MemberRecord   map[string]any
	RelayRecord    map[string]any
	ReservationSHA string
	AssignmentSHA  string
	Expires        time.Time
}

func verifyCooperativeFD3(raw, pin []byte, now time.Time) (cooperativeBridgeAuthority, error) {
	var frame cooperativeFD3
	if len(raw) == 0 || len(raw) > cooperativeFD3MaxBytes ||
		decode(raw, &frame) != nil || frame.Version != cooperativeStartVersion ||
		frame.MachinePinPath != v3PinPath {
		return cooperativeBridgeAuthority{}, invalid
	}
	reservation, err := unpadded(frame.ReservationEnvelope, 2<<20)
	if err != nil {
		return cooperativeBridgeAuthority{}, invalid
	}
	bridge, err := unpadded(frame.BridgeEnvelope, 2<<20)
	if err != nil {
		return cooperativeBridgeAuthority{}, invalid
	}
	verified, err := verifyCooperativeBridgePair(reservation, bridge, pin, now)
	if err != nil {
		return cooperativeBridgeAuthority{}, invalid
	}
	verified.FD3 = frame
	return verified, nil
}

func signedCooperativePayload(raw, pin []byte, purpose string) (map[string]any, error) {
	if len(pin) != ed25519.PublicKeySize || len(raw) == 0 || len(raw) > 2<<20 {
		return nil, invalid
	}
	envelope, err := canonicalSignedJSONBounded(raw, 2<<20)
	if err != nil || !exactKeys(envelope, "schema_version", "purpose",
		"issuer_public_key_base64url", "payload_sha256", "payload_base64url",
		"signature_base64url") || integer(envelope, "schema_version") != 3 ||
		field(envelope, "purpose") != purpose {
		return nil, invalid
	}
	issuer, err := unpadded(field(envelope, "issuer_public_key_base64url"), 32)
	if err != nil || !bytes.Equal(issuer, pin) {
		return nil, invalid
	}
	payloadBytes, err := unpadded(field(envelope, "payload_base64url"), 1<<20)
	if err != nil || digest(payloadBytes) != field(envelope, "payload_sha256") {
		return nil, invalid
	}
	signature, err := unpadded(field(envelope, "signature_base64url"), 64)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pin, append([]byte(purpose+"\x00"), payloadBytes...), signature) {
		return nil, invalid
	}
	payload, err := canonicalSignedJSONBounded(payloadBytes, 1<<20)
	if err != nil {
		return nil, invalid
	}
	return payload, nil
}

func cooperativeDecimal(value string, signed bool) bool {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return false
	}
	if signed {
		number, err := strconv.ParseInt(value, 10, 64)
		return err == nil && number > 0 && strconv.FormatInt(number, 10) == value
	}
	number, err := strconv.ParseUint(value, 10, 64)
	return err == nil && number > 0 && strconv.FormatUint(number, 10) == value
}

func cooperativeEndpoint(record any, owner, group, peer int64) (string, bool) {
	e, ok := object(record)
	if !ok || !exactKeys(e, "directory", "socket_path", "owner_uid", "group_gid",
		"dir_mode", "socket_mode", "expected_peer_uid", "parent_device",
		"parent_inode", "parent_birthtime_ns") ||
		integer(e, "owner_uid") != owner || integer(e, "group_gid") != group ||
		integer(e, "expected_peer_uid") != peer || integer(e, "dir_mode") != 02750 ||
		integer(e, "socket_mode") != 0660 ||
		!cooperativeDecimal(field(e, "parent_device"), false) ||
		!cooperativeDecimal(field(e, "parent_inode"), false) ||
		!cooperativeDecimal(field(e, "parent_birthtime_ns"), true) {
		return "", false
	}
	path, dir := field(e, "socket_path"), field(e, "directory")
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 103 ||
		strings.ContainsAny(path, "\x00\r\n") || !filepath.IsAbs(dir) ||
		filepath.Clean(dir) != dir || filepath.Dir(path) != dir {
		return "", false
	}
	return path, true
}

func verifyCooperativeBridgePair(reservationEnvelope, bridgeEnvelope, pin []byte,
	now time.Time) (cooperativeBridgeAuthority, error) {
	var empty cooperativeBridgeAuthority
	reservation, err := signedCooperativePayload(reservationEnvelope, pin,
		cooperativeReservationPurpose)
	if err != nil || !exactKeys(reservation, "contract", "kind", "schema_version",
		"host_id", "issued_at", "expires_at", "installed_plan_receipt_sha256",
		"assignment", "adapter_transport", "endpoints", "bridge_launch_sha256",
		"measurement_binding", "admission_challenge_sha256", "qualification_provider") ||
		field(reservation, "contract") != "machine/v3" ||
		field(reservation, "kind") != "soul-cooperative-reservation" ||
		integer(reservation, "schema_version") != 3 ||
		field(reservation, "adapter_transport") != "brokered-b" {
		return empty, invalid
	}
	bridgeAssignment, err := signedCooperativePayload(bridgeEnvelope, pin,
		cooperativeBridgePurpose)
	if err != nil || !exactKeys(bridgeAssignment, "contract", "kind", "schema_version",
		"host_id", "installation_id", "start_id", "launch_id", "plan_id",
		"plan_digest", "hq_epoch", "expires_at", "reservation_sha256",
		"bridge_launch_sha256", "bridge", "endpoints") ||
		field(bridgeAssignment, "contract") != "machine/v3" ||
		field(bridgeAssignment, "kind") != "soul-cooperative-bridge-assignment" ||
		integer(bridgeAssignment, "schema_version") != 3 ||
		field(bridgeAssignment, "reservation_sha256") != digest(reservationEnvelope) {
		return empty, invalid
	}
	a, ok := object(reservation["assignment"])
	if !ok || !idPattern.MatchString(field(a, "installation_id")) ||
		!idPattern.MatchString(field(a, "soul_id")) ||
		!startPattern.MatchString(field(a, "start_id")) ||
		!launchPattern.MatchString(field(a, "launch_id")) ||
		!idPattern.MatchString(field(a, "plan_id")) ||
		!hexPattern.MatchString(field(a, "plan_digest")) ||
		!hexPattern.MatchString(field(a, "hq_epoch")) ||
		!idPattern.MatchString(field(reservation, "host_id")) {
		return empty, invalid
	}
	for _, key := range []string{"installation_id", "start_id", "launch_id",
		"plan_id", "plan_digest", "hq_epoch"} {
		if field(a, key) != field(bridgeAssignment, key) {
			return empty, invalid
		}
	}
	if field(reservation, "host_id") != field(bridgeAssignment, "host_id") ||
		field(reservation, "expires_at") != field(bridgeAssignment, "expires_at") ||
		field(a, "expires_at") != field(reservation, "expires_at") ||
		field(reservation, "bridge_launch_sha256") != field(bridgeAssignment, "bridge_launch_sha256") ||
		!validDigest(field(reservation, "bridge_launch_sha256")) {
		return empty, invalid
	}
	issued, e1 := time.Parse(time.RFC3339Nano, field(reservation, "issued_at"))
	expires, e2 := time.Parse(time.RFC3339Nano, field(reservation, "expires_at"))
	if e1 != nil || e2 != nil || now.Before(issued) || !now.Before(expires) ||
		!expires.After(issued) || expires.Sub(issued) > 30*time.Second {
		return empty, invalid
	}
	b, ok := object(bridgeAssignment["bridge"])
	if !ok || !exactKeys(b, "account", "uid", "gid", "state_root",
		"state_root_mode", "executable_path", "executable_sha256",
		"sandbox_profile_path", "sandbox_profile_sha256", "argv") ||
		integer(b, "uid") <= 0 || integer(b, "uid") != integer(b, "gid") ||
		integer(b, "uid") == integer(a, "runner_uid") ||
		integer(b, "uid") == integer(a, "hq_uid") ||
		integer(a, "runner_uid") == integer(a, "hq_uid") ||
		integer(b, "uid") > 1<<32-1 ||
		integer(a, "runner_uid") <= 0 || integer(a, "hq_uid") <= 0 ||
		integer(a, "runner_uid") > 1<<32-1 ||
		integer(a, "hq_uid") > 1<<32-1 ||
		integer(a, "runner_gid") <= 0 || field(b, "account") == "" ||
		field(b, "account") == field(a, "runner_account") ||
		field(b, "state_root_mode") != "0700" ||
		!filepath.IsAbs(field(b, "state_root")) ||
		filepath.Clean(field(b, "state_root")) != field(b, "state_root") ||
		!validDigest(field(b, "executable_sha256")) ||
		!validDigest(field(b, "sandbox_profile_sha256")) {
		return empty, invalid
	}
	bridgeBytes, err := canonicalBytes(b)
	if err != nil || digest(bridgeBytes) != field(reservation, "bridge_launch_sha256") {
		return empty, invalid
	}
	endpoints, ok := object(bridgeAssignment["endpoints"])
	primaryEndpoints, primaryOK := object(reservation["endpoints"])
	if !ok || !primaryOK || !exactKeys(endpoints, "broker", "member", "relay") ||
		!exactKeys(primaryEndpoints, "admission", "member", "relay") ||
		!sameValue(endpoints["member"], primaryEndpoints["member"]) ||
		!sameValue(endpoints["relay"], primaryEndpoints["relay"]) {
		return empty, invalid
	}
	bridgeUID, runnerUID, runnerGID, hqUID := integer(b, "uid"),
		integer(a, "runner_uid"), integer(a, "runner_gid"), integer(a, "hq_uid")
	broker, bOK := cooperativeEndpoint(endpoints["broker"], hqUID, bridgeUID, bridgeUID)
	member, mOK := cooperativeEndpoint(endpoints["member"], runnerUID, bridgeUID, bridgeUID)
	relay, rOK := cooperativeEndpoint(endpoints["relay"], bridgeUID, runnerGID, runnerUID)
	if !bOK || !mOK || !rOK || broker == member || broker == relay ||
		member == relay || filepath.Dir(broker) == filepath.Dir(member) ||
		filepath.Dir(broker) == filepath.Dir(relay) ||
		filepath.Dir(member) == filepath.Dir(relay) {
		return empty, invalid
	}
	argv, ok := array(b["argv"])
	want := []string{"/usr/bin/sandbox-exec", "-D", "BROKER_SOCKET=" + broker,
		"-D", "MEMBER_SOCKET=" + member, "-D", "RELAY_SOCKET=" + relay,
		"-f", field(b, "sandbox_profile_path"), field(b, "executable_path"),
		"--assignment-fd", "3", "--proof-fd", "4", "--status-fd", "5"}
	if !ok || len(argv) != len(want) ||
		!filepath.IsAbs(field(b, "executable_path")) ||
		filepath.Clean(field(b, "executable_path")) != field(b, "executable_path") ||
		!filepath.IsAbs(field(b, "sandbox_profile_path")) ||
		filepath.Clean(field(b, "sandbox_profile_path")) != field(b, "sandbox_profile_path") {
		return empty, invalid
	}
	for i, arg := range want {
		if argv[i] != arg {
			return empty, invalid
		}
	}
	return cooperativeBridgeAuthority{BridgeUID: uint32(bridgeUID),
		RunnerUID: uint32(runnerUID), HQUID: uint32(hqUID),
		HostID: field(reservation, "host_id"), SoulID: field(a, "soul_id"),
		Installation: field(a, "installation_id"), Start: field(a, "start_id"),
		Launch: field(a, "launch_id"), Plan: field(a, "plan_id"),
		PlanDigest: field(a, "plan_digest"), Epoch: field(a, "hq_epoch"),
		BrokerPath: broker, MemberPath: member, RelayPath: relay,
		BrokerRecord:   endpoints["broker"].(map[string]any),
		MemberRecord:   endpoints["member"].(map[string]any),
		RelayRecord:    endpoints["relay"].(map[string]any),
		ReservationSHA: digest(reservationEnvelope), AssignmentSHA: digest(bridgeEnvelope),
		Expires: expires}, nil
}

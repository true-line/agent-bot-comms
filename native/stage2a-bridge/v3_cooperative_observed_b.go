package main

import (
	"encoding/base64"
	"strconv"
	"time"
)

const cooperativeBObservedPurpose = "agent-bot/soul-cooperative-b-observed/v3"

// Verify A's independent live observation of this native B and the relay
// socket. FD5 supplied the bind receipt and socket hint; neither is authority.
func verifyCooperativeBObserved(encoded string, a cooperativeBridgeAuthority,
	pin []byte, bindReceipt string, relay endpoint, socketBirthNS int64, now time.Time,
	selfMatches func(bridge, launcher map[string]any) bool) (string, time.Time, error) {
	var empty time.Time
	raw, err := unpadded(encoded, 8192)
	if err != nil || !validDigest(bindReceipt) || socketBirthNS <= 0 ||
		selfMatches == nil || !cooperativeEndpointIdentityMatches(a.RelayRecord, relay, true) {
		return "", empty, invalid
	}
	p, err := signedCooperativePayload(raw, pin, cooperativeBObservedPurpose)
	if err != nil || !exactKeys(p, "contract", "kind", "schema_version",
		"reservation_sha256", "bridge_assignment_sha256", "bind_receipt_sha256",
		"installation_id", "start_id", "launch_id", "plan_id", "plan_digest",
		"hq_epoch", "grant_nonce", "launcher", "bridge", "relay_socket",
		"relay_socket_birthtime_ns", "observed_at", "expires_at") ||
		field(p, "contract") != "machine/v3" ||
		field(p, "kind") != "soul-cooperative-b-observed" ||
		integer(p, "schema_version") != 3 ||
		field(p, "reservation_sha256") != a.ReservationSHA ||
		field(p, "bridge_assignment_sha256") != a.AssignmentSHA ||
		field(p, "bind_receipt_sha256") != bindReceipt ||
		field(p, "installation_id") != a.Installation ||
		field(p, "start_id") != a.Start ||
		field(p, "launch_id") != a.Launch ||
		field(p, "plan_id") != a.Plan ||
		field(p, "plan_digest") != a.PlanDigest ||
		field(p, "hq_epoch") != a.Epoch {
		return "", empty, invalid
	}
	nonce, err := base64.RawURLEncoding.DecodeString(field(p, "grant_nonce"))
	if err != nil || len(nonce) != 32 ||
		base64.RawURLEncoding.EncodeToString(nonce) != field(p, "grant_nonce") {
		return "", empty, invalid
	}
	bridge, bridgeOK := object(p["bridge"])
	launcher, launcherOK := object(p["launcher"])
	if !bridgeOK || !launcherOK || !liveRoleShape(bridge, a.BridgeUID) ||
		!liveRoleShape(launcher, a.BridgeUID) || !selfMatches(bridge, launcher) {
		return "", empty, invalid
	}
	socket, ok := object(p["relay_socket"])
	if !ok || !exactKeys(socket, "path", "socket") ||
		field(socket, "path") != relay.Path {
		return "", empty, invalid
	}
	node, ok := object(socket["socket"])
	if !ok || !exactKeys(node, "uid", "gid", "device", "inode", "mode") ||
		integer(node, "uid") != int64(relay.Socket.UID) ||
		integer(node, "gid") != int64(relay.Socket.GID) ||
		integer(node, "mode") != int64(relay.Socket.Mode) ||
		field(node, "device") != strconv.FormatUint(relay.Socket.Device, 10) ||
		field(node, "inode") != strconv.FormatUint(relay.Socket.Inode, 10) ||
		field(p, "relay_socket_birthtime_ns") != strconv.FormatInt(socketBirthNS, 10) {
		return "", empty, invalid
	}
	observed, e1 := time.Parse(time.RFC3339Nano, field(p, "observed_at"))
	expires, e2 := time.Parse(time.RFC3339Nano, field(p, "expires_at"))
	if e1 != nil || e2 != nil || observed.After(now) || !observed.Before(expires) ||
		!now.Before(expires) || !now.Before(a.Expires) {
		return "", empty, invalid
	}
	if a.Expires.Before(expires) {
		expires = a.Expires
	}
	return digest(raw), expires, nil
}

func liveRoleShape(role map[string]any, uid uint32) bool {
	return exactKeys(role, "pid", "uid", "gid", "start_seconds", "start_micros") &&
		integer(role, "pid") > 1 && integer(role, "uid") == int64(uid) &&
		integer(role, "gid") > 0 && integer(role, "start_seconds") > 0 &&
		integer(role, "start_micros") >= 0 && integer(role, "start_micros") < 1000000
}

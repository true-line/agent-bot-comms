package main

// These records belong only to the one-use observed-body local test. Their
// distinct schemas prevent a v2 exact-body or cooperative-v3 frame from
// being interpreted as an observed-body authorization.
type observedSelectors struct {
	InstallationID        string `json:"installation_id"`
	StartID               string `json:"start_id"`
	LaunchID              string `json:"launch_id"`
	PlanID                string `json:"plan_id"`
	PlanDigest            string `json:"plan_digest"`
	ReservationDigest     string `json:"reservation_digest"`
	AssignmentEnvelopeSHA string `json:"assignment_envelope_sha256"`
	AuthorityEnvelopeSHA  string `json:"authority_envelope_sha256"`
	MemberSelectorsSHA256 string `json:"member_selectors_sha256"`
}

type observedPeer struct {
	UID                uint32 `json:"uid"`
	PID                uint32 `json:"pid"`
	PIDVersion         uint64 `json:"pid_version"`
	StartSeconds       uint64 `json:"start_seconds"`
	StartMicros        uint32 `json:"start_micros"`
	ParentPID          uint32 `json:"parent_pid"`
	ParentUID          uint32 `json:"parent_uid"`
	ParentStartSeconds uint64 `json:"parent_start_seconds"`
	ParentStartMicros  uint32 `json:"parent_start_micros"`
}

type observedIngressCore struct {
	Schema                 string            `json:"schema"`
	Kind                   string            `json:"kind"`
	Selectors              observedSelectors `json:"selectors"`
	BindReceiptSHA256      string            `json:"bind_receipt_sha256"`
	Peer                   observedPeer      `json:"peer"`
	PeerSHA256             string            `json:"peer_sha256"`
	ObservedBodySHA256     string            `json:"observed_body_sha256"`
	ObservedHeadersSHA256  string            `json:"observed_headers_sha256"`
	StaticProjectionSHA256 string            `json:"static_projection_sha256"`
	ObservedBriefSHA256    string            `json:"observed_brief_sha256"`
	OwnerPromptSHA256      string            `json:"owner_prompt_sha256"`
	BodyProfile            string            `json:"body_profile"`
	DigestKind             string            `json:"digest_kind"`
	TargetReceivedAt       string            `json:"target_received_at"`
	AttemptID              string            `json:"attempt_id"`
}

type observedIngressPayload struct {
	Core             observedIngressCore `json:"core"`
	IngressOriginMAC string              `json:"ingress_origin_mac"`
}

type observedPrewrite struct {
	Schema                      string            `json:"schema"`
	Selectors                   observedSelectors `json:"selectors"`
	BindReceiptSHA256           string            `json:"bind_receipt_sha256"`
	AuthorizationEnvelopeSHA256 string            `json:"authorization_envelope_sha256"`
	IngressCoreSHA256           string            `json:"ingress_core_sha256"`
	ObservedBodySHA256          string            `json:"observed_body_sha256"`
	ObservedHeadersSHA256       string            `json:"observed_headers_sha256"`
	StaticProjectionSHA256      string            `json:"static_projection_sha256"`
	OwnerPromptSHA256           string            `json:"owner_prompt_sha256"`
	Peer                        observedPeer      `json:"peer"`
	PeerSHA256                  string            `json:"peer_sha256"`
	ResponseWireSHA256          string            `json:"response_wire_sha256"`
	ResponseWireBytes           int               `json:"response_wire_bytes"`
	HTTPStatus                  int               `json:"http_status"`
}

type observedCompletionCore struct {
	observedPrewrite
	PrewriteReceipt  string `json:"prewrite_receipt"`
	WriteStartedAt   string `json:"write_started_at"`
	WriteCompletedAt string `json:"write_completed_at"`
	DigestKind       string `json:"digest_kind"`
}

type observedCompletionPayload struct {
	Core                observedCompletionCore `json:"core"`
	CompletionOriginMAC string                 `json:"completion_origin_mac"`
}

package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	bindContext             = "agent-bot-stage2a-bridge-bind-v2"
	completionSubkeyContext = "agent-bot-stage2a-b-completion-subkey-v1"
	completionOriginContext = "agent-bot-stage2a-b-completion-origin-v1"
	relayIngressOp          = "bridge.relay.ingress.v1"
	relayPrewriteOp         = "bridge.relay.prewrite.v1"
	relayCompletionOp       = "bridge.relay.complete.v1"
	ioTimeout               = 5 * time.Second
	// HQ may perform a lease check, authorize the turn, and recheck the lease.
	relayIngressTimeout = 20 * time.Second
	// HQ waits for Machine's signed live-child prewrite observation.
	relayPrewriteTimeout = 20 * time.Second
	// HQ rechecks live A, then waits for Machine's signed positive receipt.
	relayCompletionTimeout = 20 * time.Second
)

var (
	errCleanupUnconfirmed = errors.New("relay cleanup identity unconfirmed")
	idPattern             = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
	hexPattern            = regexp.MustCompile("^[0-9a-f]{64}$")
	startPattern          = regexp.MustCompile("^st_[0-9a-f]{24}$")
	launchPattern         = regexp.MustCompile("^ln_[0-9a-f]{24}$")
	queryPattern          = regexp.MustCompile("^[a-zA-Z0-9._=&%-]{0,128}$")
)

func deadline() time.Time { return time.Now().Add(ioTimeout) }

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && hexPattern.MatchString(value[7:])
}

type identity struct {
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Mode   uint32 `json:"mode"`
}

type endpoint struct {
	Path   string   `json:"path"`
	Parent identity `json:"parent"`
	Socket identity `json:"socket"`
}

type selectors struct {
	Installation string `json:"installation_id"`
	Start        string `json:"start_id"`
	Launch       string `json:"launch_id"`
	Plan         string `json:"plan_id"`
	PlanDigest   string `json:"plan_digest"`
	Reservation  string `json:"reservation_digest"`
}

type assignment struct {
	Version         string    `json:"version"`
	Selectors       selectors `json:"selectors"`
	Epoch           string    `json:"hq_epoch"`
	BridgeUID       uint32    `json:"bridge_uid"`
	HQUID           uint32    `json:"hq_uid"`
	RunnerUID       uint32    `json:"runner_uid"`
	Expires         time.Time `json:"expires_at"`
	Broker          endpoint  `json:"broker"`
	Relay           endpoint  `json:"relay"`
	Model           string    `json:"model"`
	RequestDigest   string    `json:"request_sha256"`
	HeadersDigest   string    `json:"headers_sha256"`
	ClientKeyDigest string    `json:"client_key_sha256"`
	HTTPHost        string    `json:"http_host"`
	MessagesQuery   string    `json:"messages_query"`
}

func (a assignment) validate() error {
	s := a.Selectors
	uidOK := func(id uint32) bool { return id >= 300 && id <= 399 }
	if a.Version != "stage2a-b-assignment/v2" || !idPattern.MatchString(s.Installation) ||
		!startPattern.MatchString(s.Start) || !launchPattern.MatchString(s.Launch) ||
		!idPattern.MatchString(s.Plan) || !hexPattern.MatchString(s.PlanDigest) || !validDigest(s.Reservation) ||
		!hexPattern.MatchString(a.Epoch) || !idPattern.MatchString(a.Model) ||
		!validDigest(a.RequestDigest) || !validDigest(a.HeadersDigest) || !validDigest(a.ClientKeyDigest) ||
		!idPattern.MatchString(a.HTTPHost) ||
		!queryPattern.MatchString(a.MessagesQuery) || !time.Now().Before(a.Expires) ||
		!uidOK(a.BridgeUID) || !uidOK(a.HQUID) || !uidOK(a.RunnerUID) ||
		a.BridgeUID == a.HQUID || a.BridgeUID == a.RunnerUID || a.HQUID == a.RunnerUID ||
		a.Broker.Path == a.Relay.Path || filepath.Dir(a.Broker.Path) == filepath.Dir(a.Relay.Path) {
		return invalid
	}
	for _, e := range []endpoint{a.Broker, a.Relay} {
		if !filepath.IsAbs(e.Path) || filepath.Clean(e.Path) != e.Path || len(e.Path) > 103 ||
			strings.ContainsAny(e.Path, "\x00\r\n") || e.Parent.Inode == 0 || e.Parent.Mode != 02750 ||
			e.Socket.Mode != 0660 || e.Parent.UID != e.Socket.UID || e.Parent.GID != e.Socket.GID {
			return invalid
		}
	}
	if a.Broker.Parent.UID != a.HQUID || a.Broker.Parent.GID != a.BridgeUID || a.Broker.Socket.Inode == 0 ||
		a.Relay.Parent.UID != a.BridgeUID || a.Relay.Parent.GID != a.RunnerUID ||
		a.Relay.Socket.Inode != 0 || a.Relay.Socket.Device != 0 {
		return invalid
	}
	return nil
}

func observe(path string, kind os.FileMode) (identity, error) {
	stat, err := os.Lstat(path)
	if err != nil {
		return identity{}, err
	}
	native, ok := stat.Sys().(*syscall.Stat_t)
	if !ok || stat.Mode().Type()&^(os.ModeSetgid|os.ModeSetuid|os.ModeSticky) != kind {
		return identity{}, invalid
	}
	return identity{native.Uid, native.Gid, uint64(native.Dev), uint64(native.Ino), uint32(native.Mode) & 07777}, nil
}

func (e endpoint) current() bool {
	parent, err := observe(filepath.Dir(e.Path), os.ModeDir)
	if err != nil || parent != e.Parent {
		return false
	}
	socket, err := observe(e.Path, os.ModeSocket)
	return err == nil && socket == e.Socket
}

type checkPeer func(*net.UnixConn) (uint32, error)
type capturePeer func(*net.UnixConn) (peerProcessSnapshot, error)

func validRelayPeer(peer peerProcessSnapshot, uid uint32) bool {
	return peer.Peer.UID == uid && peer.ParentUID == uid &&
		peer.Peer.PID > 1 && peer.Peer.PIDVersion > 0 &&
		peer.StartSeconds > 0 && peer.StartMicros < 1000000 &&
		peer.ParentPID > 1 && peer.ParentStartSeconds > 0 && peer.ParentStartMicros < 1000000
}

func peerMatches(conn *net.UnixConn, want uint32, check checkPeer) bool {
	if check == nil {
		return false
	}
	got, err := check(conn)
	return err == nil && got == want
}

type brokerReply struct {
	ID          string          `json:"id"`
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	HostRefusal *struct {
		Code          string `json:"code"`
		Explanation   string `json:"explanation"`
		CorrelationID string `json:"correlation_id"`
	} `json:"host_refusal"`
	Refusal json.RawMessage `json:"refusal"`
}

func decodeBrokerResult(data []byte, id, op string, out any) error {
	var reply brokerReply
	if decode(data, &reply) != nil || reply.ID != id {
		return invalid
	}
	if !reply.OK {
		if (op == "bridge.member.observe.v3" || op == "bridge.member.observe.cooperative.v3") && reply.HostRefusal != nil &&
			reply.HostRefusal.Code == "host.launch_busy" &&
			reply.HostRefusal.Explanation != "" &&
			reply.HostRefusal.CorrelationID != "" &&
			len(reply.Refusal) == 0 && len(reply.Result) == 0 {
			return errObservationPending
		}
		return invalid
	}
	if reply.HostRefusal != nil || len(reply.Refusal) != 0 || decode(reply.Result, out) != nil {
		return invalid
	}
	return nil
}

type completionCore struct {
	Selectors          selectors      `json:"selectors"`
	BindReceiptSHA256  string         `json:"bind_receipt_sha256"`
	PrewriteReceipt    string         `json:"prewrite_receipt"`
	Peer               map[string]any `json:"peer"`
	PeerSHA256         string         `json:"peer_sha256"`
	RequestSHA256      string         `json:"request_sha256"`
	PromptSHA256       string         `json:"prompt_sha256"`
	Model              string         `json:"model"`
	ResponseWireSHA256 string         `json:"response_wire_sha256"`
	ResponseWireBytes  int            `json:"response_wire_bytes"`
	HTTPStatus         int            `json:"http_status"`
	WriteStartedAt     time.Time      `json:"write_started_at"`
	WriteCompletedAt   time.Time      `json:"write_completed_at"`
}

type completionPayload struct {
	completionCore
	CompletionOriginMAC string `json:"completion_origin_mac"`
}

func deriveCompletionSubkey(key []byte, reservation string) ([]byte, error) {
	if len(key) != 32 || !validDigest(reservation) {
		return nil, invalid
	}
	mac := hmac.New(sha256.New, key)
	io.WriteString(mac, completionSubkeyContext)
	mac.Write([]byte{0})
	io.WriteString(mac, reservation)
	return mac.Sum(nil), nil
}

func completionOriginMAC(subkey []byte, core completionCore) (string, error) {
	if len(subkey) != 32 {
		return "", invalid
	}
	canonical, err := canonicalJSONValue(core)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, subkey)
	io.WriteString(mac, completionOriginContext)
	mac.Write([]byte{0})
	mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

type prewritePayload struct {
	Selectors          selectors      `json:"selectors"`
	BindReceiptSHA256  string         `json:"bind_receipt_sha256"`
	RequestSHA256      string         `json:"request_sha256"`
	PromptSHA256       string         `json:"prompt_sha256"`
	Model              string         `json:"model"`
	Peer               map[string]any `json:"peer"`
	PeerSHA256         string         `json:"peer_sha256"`
	ResponseWireSHA256 string         `json:"response_wire_sha256"`
	ResponseWireBytes  int            `json:"response_wire_bytes"`
	HTTPStatus         int            `json:"http_status"`
}

type broker struct {
	conn    *net.UnixConn
	frames  chan []byte
	dead    chan struct{}
	waiting atomic.Bool
}

func openBroker(ctx context.Context, config assignment, check checkPeer) (*broker, error) {
	if !config.Broker.current() {
		return nil, invalid
	}
	dialer := net.Dialer{Deadline: deadline()}
	stream, err := dialer.DialContext(ctx, "unix", config.Broker.Path)
	if err != nil {
		return nil, invalid
	}
	conn := stream.(*net.UnixConn)
	if !peerMatches(conn, config.HQUID, check) || !config.Broker.current() {
		conn.Close()
		return nil, invalid
	}
	b := &broker{conn: conn, frames: make(chan []byte, 1), dead: make(chan struct{})}
	go func() {
		defer close(b.dead)
		defer conn.Close()
		scan := bufio.NewScanner(conn)
		scan.Buffer(make([]byte, 4096), 32768)
		for scan.Scan() {
			if len(scan.Bytes()) == 0 || !b.waiting.CompareAndSwap(true, false) {
				return
			}
			select {
			case b.frames <- append([]byte(nil), scan.Bytes()...):
			default:
				// No reader means the broker sent an unsolicited or pipelined frame.
				return
			}
		}
	}()
	return b, nil
}

func (b *broker) call(ctx context.Context, id, op string, payload, out any) error {
	encoded, err := json.Marshal(struct {
		ID      string `json:"id"`
		Op      string `json:"op"`
		Payload any    `json:"payload"`
	}{id, op, payload})
	if err != nil {
		return invalid
	}
	if b.conn.SetWriteDeadline(deadline()) != nil || !b.waiting.CompareAndSwap(false, true) {
		return invalid
	}
	// Buffer the one solicited frame before the caller can begin its select.
	if _, err = b.conn.Write(append(encoded, '\n')); err != nil {
		return invalid
	}
	timeout := ioTimeout
	switch op {
	case relayIngressOp, "bridge.member-policy.v3", "bridge.ready.cooperative.v3":
		timeout = relayIngressTimeout
	case relayPrewriteOp:
		timeout = relayPrewriteTimeout
	case relayCompletionOp:
		timeout = relayCompletionTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return invalid
	case <-b.dead:
		return invalid
	case <-timer.C:
		return invalid
	case data := <-b.frames:
		return decodeBrokerResult(data, id, op, out)
	}
}

type challenge struct {
	Nonce     string    `json:"nonce"`
	Algorithm string    `json:"algorithm"`
	Context   string    `json:"context"`
	Epoch     string    `json:"hq_epoch"`
	Expires   time.Time `json:"expires_at"`
}

func (b *broker) bind(ctx context.Context, config assignment, key []byte) (string, error) {
	defer clear(key)
	var c challenge
	if b.call(ctx, "challenge", "bridge.bind.v2.challenge", config.Selectors, &c) != nil ||
		c.Algorithm != "hmac-sha256" || c.Context != bindContext || c.Epoch != config.Epoch ||
		!hexPattern.MatchString(c.Nonce) || !time.Now().Before(c.Expires) || c.Expires.After(config.Expires) {
		return "", invalid
	}
	s := config.Selectors
	mac := hmac.New(sha256.New, key)
	io.WriteString(mac, strings.Join([]string{bindContext, c.Nonce, c.Epoch, s.Installation, s.Start, s.Launch,
		s.Plan, s.PlanDigest, s.Reservation, strconv.FormatUint(uint64(config.BridgeUID), 10), config.Broker.Path}, "\x00"))
	var bound struct {
		Receipt string `json:"bind_receipt"`
	}
	if b.call(ctx, "bind", "bridge.bind.v2", struct {
		selectors
		Proof string `json:"proof"`
	}{s, hex.EncodeToString(mac.Sum(nil))}, &bound) != nil || !hexPattern.MatchString(bound.Receipt) ||
		!time.Now().Before(c.Expires) || !config.Broker.current() {
		return "", invalid
	}
	return digest([]byte(bound.Receipt)), nil
}

func run(ctx context.Context, config assignment, key []byte, status io.WriteCloser,
	check checkPeer, capture capturePeer,
	writeSuccess func(*net.UnixConn, preparedHTTP) (httpWrite, error)) (runErr error) {
	defer clear(key)
	b, err := openBroker(ctx, config, check)
	if err != nil {
		return errors.New("broker identity or connection rejected")
	}
	defer b.conn.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-b.dead:
			cancel()
		case <-ctx.Done():
		}
	}()
	// Keep only a purpose-scoped subkey after bind clears the raw FD4 proof.
	completionKey, err := deriveCompletionSubkey(key, config.Selectors.Reservation)
	if err != nil {
		return errors.New("completion subkey derivation rejected")
	}
	defer clear(completionKey)
	receipt, err := b.bind(ctx, config, key)
	if err != nil {
		return errors.New("broker bind rejected")
	}
	listener, relay, cleanup, err := listenRelay(config.Relay)
	if err != nil {
		return errors.Join(errors.New("relay endpoint rejected"), err)
	}
	defer func() { runErr = errors.Join(runErr, cleanup()) }()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	if ctx.Err() != nil || !config.Broker.current() || !relay.current() {
		return invalid
	}
	if json.NewEncoder(status).Encode(struct {
		Digest string   `json:"bind_receipt_sha256"`
		Socket identity `json:"relay_socket"`
	}{receipt, relay.Socket}) != nil || status.Close() != nil {
		return errors.New("could not report relay readiness")
	}
	attempted := false
	for {
		if err := listener.SetDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
			if ctx.Err() != nil {
				select {
				case <-b.dead:
					return errors.New("broker disconnected")
				default:
					return nil
				}
			}
			return errors.New("relay listener deadline unavailable")
		}
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() == nil {
				if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					if !relay.current() || !config.Broker.current() {
						return errors.New("endpoint identity changed")
					}
					continue
				}
				return errors.New("relay listener failed")
			}
			select {
			case <-b.dead:
				return errors.New("broker disconnected")
			default:
				return nil
			}
		}
		if !relay.current() || !config.Broker.current() {
			conn.Close()
			return errors.New("endpoint identity changed")
		}
		if !peerMatches(conn, config.RunnerUID, check) {
			conn.Close()
			continue
		}
		if capture == nil {
			conn.Close()
			continue
		}
		peer, err := capture(conn)
		if err != nil || !validRelayPeer(peer, config.RunnerUID) {
			conn.Close()
			continue
		}
		stopConn := context.AfterFunc(ctx, func() { conn.Close() })
		err = serve(ctx, conn, b, config, relay, receipt, peer, capture, completionKey,
			&attempted, writeSuccess)
		stopConn()
		conn.Close()
		if err != nil {
			return err
		}
	}
}

func listenRelay(e endpoint) (*net.UnixListener, endpoint, func() error, error) {
	parent, err := observe(filepath.Dir(e.Path), os.ModeDir)
	if err != nil || parent != e.Parent {
		return nil, e, nil, invalid
	}
	if _, err = os.Lstat(e.Path); !os.IsNotExist(err) {
		return nil, e, nil, invalid
	}
	// Before listen, make a socket visible only to its creating UID.
	mask := syscall.Umask(0077)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: e.Path, Net: "unix"})
	syscall.Umask(mask)
	if err != nil {
		return nil, e, nil, invalid
	}
	l.SetUnlinkOnClose(false)
	created, err := observe(e.Path, os.ModeSocket)
	owned := e
	owned.Socket = created
	cleanup := func() error {
		l.Close()
		if !owned.current() {
			return errCleanupUnconfirmed
		}
		if os.Remove(owned.Path) != nil {
			return errors.New("relay cleanup failed")
		}
		return nil
	}
	if err != nil || created.UID != e.Socket.UID || created.GID != e.Socket.GID || !owned.current() {
		l.Close()
		return nil, e, nil, errCleanupUnconfirmed
	}
	if os.Chmod(e.Path, os.FileMode(e.Socket.Mode)) != nil {
		return nil, e, nil, errors.Join(invalid, cleanup())
	}
	owned.Socket.Mode = e.Socket.Mode
	if !owned.current() {
		return nil, e, nil, errors.Join(invalid, cleanup())
	}
	return l, owned, cleanup, nil
}

package main

import (
	"context"
	"net"
	"time"
)

type cooperativePeerAdmission struct {
	MemberIndex int
	Peer        peerProcessSnapshot
	MemberLease cooperativeMemberLease
	Warrant     cooperativePeerWarrant
}

func cooperativeResultMatchesMember(out *qualificationResult, member v3Member) bool {
	return out != nil && out.valid(member.Policy.Model) &&
		out.Text == member.ResponseText
}

func (b *broker) serveCooperativePeer(ctx context.Context, conn *net.UnixConn,
	a cooperativeBridgeAuthority, policy v3Authority, observation v3Observation,
	ready cooperativeReadyState, relay endpoint, admitted cooperativePeerAdmission,
	attempted *bool) error {
	member := policy.Members[admitted.MemberIndex]
	config := member.Policy
	config.Broker = policy.FD3.Broker
	current := func() bool {
		peer, err := observePeerProcess(conn)
		return err == nil && peer == admitted.Peer &&
			liveV3Child(observation.Children[admitted.MemberIndex], member) &&
			cooperativeSelfMatches(ready.Observed.Bridge, ready.Observed.Launcher) &&
			cooperativeEndpointCurrent(a.BrokerRecord, policy.FD3.Broker) &&
			cooperativeEndpointCurrent(a.RelayRecord, relay) &&
			currentCooperativeRelayBirth(relay, ready.BirthNS) == nil &&
			time.Now().Before(ready.Expires) && time.Now().Before(ready.Lease.Expires) &&
			time.Now().Before(admitted.MemberLease.Expires) &&
			time.Now().Before(admitted.Warrant.Expires)
	}
	authorize := func(model, promptSHA string, out *qualificationResult) error {
		if !current() || !validDigest(promptSHA) || model != config.Model {
			return invalid
		}
		request := struct {
			MemberID       string `json:"member_id"`
			MemberLaunch   string `json:"member_launch_id"`
			Selector       string `json:"member_selector"`
			ReadySHA       string `json:"ready_sha256"`
			BLeaseSHA      string `json:"b_lease_sha256"`
			BLeaseSequence int64  `json:"b_lease_sequence"`
			MemberLeaseSHA string `json:"member_lease_sha256"`
			MemberLeaseSeq int64  `json:"member_lease_sequence"`
			PeerSHA        string `json:"peer_warrant_sha256"`
			Model          string `json:"model"`
			PromptSHA      string `json:"prompt_sha256"`
		}{member.ID, member.Launch, member.Selector, ready.SHA,
			ready.Lease.SHA, ready.Lease.Sequence, admitted.MemberLease.SHA,
			admitted.MemberLease.Sequence, admitted.Warrant.SHA, model, promptSHA}
		if b.call(ctx, "cooperative-ingress-"+admitted.Warrant.SHA,
			"bridge.relay.ingress.cooperative.v3", request, out) != nil ||
			!cooperativeResultMatchesMember(out, member) {
			return invalid
		}
		return nil
	}
	return serveWithIngress(ctx, conn, config, relay, attempted, authorize, current)
}

// H forwards this same-bound request to A. Neither H's reply nor the A
// signature alone authorizes the socket: B rechecks the accepted kernel peer,
// A-observed ACP parent, B process, leases, and relay before returning.
func (b *broker) admitCooperativePeer(ctx context.Context, conn *net.UnixConn,
	a cooperativeBridgeAuthority, policy v3Authority, observation v3Observation,
	ready cooperativeReadyState, relay endpoint,
	priorMemberLeases [2]cooperativeMemberLease) (cooperativePeerAdmission, error) {
	peer, err := observePeerProcess(conn)
	if err != nil {
		return cooperativePeerAdmission{}, invalid
	}
	index, err := cooperativePeerMember(policy, observation, peer)
	if err != nil || !liveV3Child(observation.Children[index], policy.Members[index]) ||
		!cooperativeSelfMatches(ready.Observed.Bridge, ready.Observed.Launcher) ||
		!cooperativeEndpointCurrent(a.BrokerRecord, policy.FD3.Broker) ||
		!cooperativeEndpointCurrent(a.RelayRecord, relay) ||
		currentCooperativeRelayBirth(relay, ready.BirthNS) != nil ||
		!time.Now().Before(ready.Lease.Expires) {
		return cooperativePeerAdmission{}, invalid
	}
	nonce, err := randomBase64Nonce()
	if err != nil {
		return cooperativePeerAdmission{}, invalid
	}
	member := policy.Members[index]
	request := struct {
		MemberID     string         `json:"member_id"`
		MemberLaunch string         `json:"member_launch_id"`
		Selector     string         `json:"member_selector"`
		ReadySHA     string         `json:"ready_sha256"`
		BLeaseSHA    string         `json:"b_lease_sha256"`
		BLeaseSeq    int64          `json:"b_lease_sequence"`
		RelaySocket  map[string]any `json:"relay_socket"`
		CLIPath      string         `json:"cli_path"`
		CLISHA       string         `json:"cli_sha256"`
		Nonce        string         `json:"challenge_nonce_base64url"`
		Peer         map[string]any `json:"peer"`
	}{member.ID, member.Launch, member.Selector, ready.SHA,
		ready.Lease.SHA, ready.Lease.Sequence, relayClaimValue(relay),
		member.CLIPath, member.CLIDigest, nonce, cooperativePeerValue(peer)}
	var reply struct {
		PeerEnvelope        string `json:"peer_envelope_base64url"`
		PeerSHA             string `json:"peer_sha256"`
		MemberLeaseEnvelope string `json:"member_lease_envelope_base64url"`
		MemberLeaseSHA      string `json:"member_lease_sha256"`
	}
	if b.call(ctx, "cooperative-peer-"+digest([]byte(nonce)),
		"bridge.peer.cooperative.v3", request, &reply) != nil ||
		!cooperativeEndpointCurrent(a.BrokerRecord, policy.FD3.Broker) ||
		!cooperativeEndpointCurrent(a.RelayRecord, relay) ||
		currentCooperativeRelayBirth(relay, ready.BirthNS) != nil ||
		!cooperativeSelfMatches(ready.Observed.Bridge, ready.Observed.Launcher) ||
		!liveV3Child(observation.Children[index], member) ||
		!time.Now().Before(ready.Lease.Expires) {
		return cooperativePeerAdmission{}, invalid
	}
	memberLease, err := verifyCooperativeMemberLease(reply.MemberLeaseEnvelope, policy,
		observation, index, ready.SHA, priorMemberLeases[index].Sequence,
		priorMemberLeases[index].SHA, ready.Expires, time.Now())
	if err != nil || reply.MemberLeaseSHA != memberLease.SHA {
		return cooperativePeerAdmission{}, invalid
	}
	warrant, err := verifyCooperativeRelayPeer(reply.PeerEnvelope, a, policy,
		observation, ready, memberLease, index, peer, nonce, relay, time.Now())
	if err != nil || reply.PeerSHA != warrant.SHA {
		return cooperativePeerAdmission{}, invalid
	}
	again, err := observePeerProcess(conn)
	if err != nil || again != peer ||
		!cooperativeEndpointCurrent(a.RelayRecord, relay) ||
		currentCooperativeRelayBirth(relay, ready.BirthNS) != nil ||
		!time.Now().Before(memberLease.Expires) || !time.Now().Before(warrant.Expires) {
		return cooperativePeerAdmission{}, invalid
	}
	return cooperativePeerAdmission{index, peer, memberLease, warrant}, nil
}

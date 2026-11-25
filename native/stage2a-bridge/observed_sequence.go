package main

// The selected R/stock first turn emits exactly two ancillary POSTs and one
// provider target. Source captures put the target either between ancillary A
// and B or after B. The A/B labels come from their separately pinned header
// profiles; a request does not self-identify its class.
type observedRequestClass uint8

const (
	observedAncillaryA observedRequestClass = iota + 1
	observedAncillaryB
	observedTarget
)

type observedSequence struct {
	ancillaryA bool
	ancillaryB bool
	target     bool
	peer       observedPeer
	peerSet    bool
}

func (s *observedSequence) acceptFrom(class observedRequestClass, peer observedPeer) error {
	if s == nil || (s.peerSet && s.peer != peer) || s.accept(class) != nil {
		return invalid
	}
	if !s.peerSet {
		s.peer, s.peerSet = peer, true
	}
	return nil
}

func (s *observedSequence) accept(class observedRequestClass) error {
	if s == nil {
		return invalid
	}
	switch class {
	case observedAncillaryA:
		if s.ancillaryA || s.ancillaryB || s.target {
			return invalid
		}
		s.ancillaryA = true
	case observedAncillaryB:
		if !s.ancillaryA || s.ancillaryB {
			return invalid
		}
		s.ancillaryB = true
	case observedTarget:
		if !s.ancillaryA || s.target {
			return invalid
		}
		s.target = true
	default:
		return invalid
	}
	return nil
}

func (s observedSequence) complete() bool {
	return s.ancillaryA && s.ancillaryB && s.target
}

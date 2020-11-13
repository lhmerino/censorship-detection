package shared

import (
	"github.com/Kkevsterrr/gopacket"
	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/reassembly"
)

// MainInterface :
//	For configuration level structs
type MainInterface interface {
	// Name : Get the name of the specific type
	Name() string

	// GetBasicInfo : Get basic identifiable information on specific type
	GetBasicInfo() string
}

type StreamMatcher interface {
	// MatchesFlow : Determine if the new connection is relevant to the specific type
	// TODO: rename to MatchesStream
	RelevantToConnection(net gopacket.Flow, transport gopacket.Flow) bool
}

// StreamStateFactory is implemented by detectors and collectors
type StreamStateFactory interface {
	StreamMatcher
	// Generate a new stream state
	NewStream(net, transport *gopacket.Flow, tcp *layers.TCP) StreamState
}

// StreamState : For storing and updating per-stream state
type StreamState interface {
	ProcessPacket(packet *gopacket.Packet, tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection)
	ProcessReassembled(sg *reassembly.ScatterGather, ac *reassembly.AssemblerContext)
}

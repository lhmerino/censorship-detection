package shared

import (
	"github.com/Kkevsterrr/gopacket"
	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/reassembly"
)

// MainInterface :
//	For configuration level structs
type MainInterface interface {
	// GetName : Get the name of the specific type
	GetName() string

	// RelevantNewConnection : Determine if the new connection is relevant to the specific type
	RelevantNewConnection(net gopacket.Flow, transport gopacket.Flow) bool

	// GetBasicInfo : Get basic identifiable information on specific type
	GetBasicInfo() string
}

// StreamInterface : For stream level structs that only process information header information from the first packet
type StreamInterface interface {
	NewStream(net, transport *gopacket.Flow, tcp *layers.TCP) interface{}
}

// ProcessPacketHeaderInterface : For stream level structs that process header information from packets
type ProcessPacketHeaderInterface interface {
	ProcessPacketHeader(someInterface interface{}, packet *gopacket.Packet, tcp *layers.TCP, ci *gopacket.CaptureInfo,
		dir *reassembly.TCPFlowDirection)
}

// ProcessPacketPayloadInterface : For stream level structs that process payload information from packets
type ProcessPacketPayloadInterface interface {
	ProcessPacketPayload(someInterface interface{}, sg *reassembly.ScatterGather, ac *reassembly.AssemblerContext)
}

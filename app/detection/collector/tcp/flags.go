package tcp

import (
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger/data"
	"github.com/Kkevsterrr/gopacket"
	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/reassembly"
)

// Flags : Config level struct for flags
type Flags struct {
	// Inherits Collector Interface
	// Inherits ProcessPacketHeader Interface
}

// FlagsStream : Stream level struct for stream
// - Array (representing each packet) of flags
type FlagsStream struct {
	flags []string
}

// ------ Flags Methods -----

// NewFlags : Creates the config level struct
func NewFlags() *Flags {
	return &Flags{}
}

// GetName : Description of this interface
func (p *Flags) GetName() string {
	return "[TCP - Flags]"
}

// RelevantNewConnection : For now, only working with TCP packets so must be true
func (p *Flags) RelevantNewConnection(net gopacket.Flow, transport gopacket.Flow) bool {
	return true
}

// GetBasicInfo : No options available - return only its name
func (p *Flags) GetBasicInfo() string {
	return p.GetName()
}

// NewStream : Create stream level struct to store the flags of each packet
func (p *Flags) NewStream(net, transport *gopacket.Flow, tcp *layers.TCP) interface{} {
	return NewFlagsStream()
}

// ProcessPacketHeader : Appends flags for packet to FlagsStream
func (p *Flags) ProcessPacketHeader(someInterface interface{}, packet *gopacket.Packet, tcp *layers.TCP,
								    ci *gopacket.CaptureInfo, dir *reassembly.TCPFlowDirection) {
	flagsStream := someInterface.(*FlagsStream)

	flagsStream.AppendFlags(tcp)
}

// GetData : Returns array (each packet) of string values of TCP Flags (e.g. "FPA")
func (p *Flags) GetData(someInterface interface{}) *data.Array {
	stream := someInterface.(*FlagsStream)

	value := stream.GetData()

	return data.NewArray(p.GetName(), value)
}

// ----- Flags Stream Methods -----

// NewFlagsStream : Creates stream level struct
func NewFlagsStream() *FlagsStream {
	flags := make([]string, 0)

	return &FlagsStream{flags: flags}
}

// AppendFlags : Append flags for this packet
func (p *FlagsStream) AppendFlags(tcp *layers.TCP) {
	p.flags = append(p.flags, convertTCPFlagsToString(tcp))
}

// GetData : Returns an array (representing each packet) of flags
func (p *FlagsStream) GetData() []string {
	return p.flags
}


// convertTCPFlagsToString :
//	Checks if flag is SET and replaces with one
//	letter character representing that flag
func convertTCPFlagsToString(tcp *layers.TCP) string {
	flags := ""

	if tcp.FIN {
		flags += "F"
	}
	if tcp.SYN {
		flags += "S"
	}
	if tcp.RST {
		flags += "R"
	}
	if tcp.PSH {
		flags += "P"
	}
	if tcp.ACK {
		flags += "A"
	}
	if tcp.URG {
		flags += "U"
	}

	return flags
}
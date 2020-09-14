package tcp

import (
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger/data"
	"github.com/Kkevsterrr/gopacket"
	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/reassembly"
)

// Ports : Config level struct for ports
type Ports struct {
	// Inherits Collector Interface
	// Inherits ProcessPacketHeader Interface
}

// PortsStream : Stream level struct for stream
//	- TCPPort is equivalent to uint16
//  - The length of the two lists must be equal
type PortsStream struct {
	srcPorts []layers.TCPPort
	dstPorts []layers.TCPPort
}

// ------ Ports Methods -----

// NewPorts : Creates the config level struct
func NewPorts() *Ports {
	return &Ports{}
}

// GetName : Description of this interface
func (p *Ports) GetName() string {
	return "[TCP - Ports]"
}

// RelevantNewConnection : For now, only working with TCP packets so must be true
func (p *Ports) RelevantNewConnection(net gopacket.Flow, transport gopacket.Flow) bool {
	return true
}

// GetBasicInfo : No options available - return only its name
func (p *Ports) GetBasicInfo() string {
	return p.GetName()
}

// NewStream : Create stream level struct to store the src and dst ports of each packet
func (p *Ports) NewStream(net, transport *gopacket.Flow, tcp *layers.TCP) interface{} {
	return NewPortsStream()
}

// ProcessPacketHeader : Appends src and dst ports to PortsStream
func (p *Ports) ProcessPacketHeader(someInterface interface{}, packet *gopacket.Packet, tcp *layers.TCP,
	ci *gopacket.CaptureInfo, dir *reassembly.TCPFlowDirection) {
	portsStream := someInterface.(*PortsStream)

	portsStream.AppendPorts(&tcp.SrcPort, &tcp.DstPort)
}

// GetData : Returns with only values of "srcPort->dstPort"
//	in the array during creation of the stream
func (p *Ports) GetData(someInterface interface{}) *data.Array {
	portsStream := someInterface.(*PortsStream)

	value := portsStream.GetData()

	return data.NewArray("[TCP - Ports]", value)
}

// ----- Ports Stream Methods -----

// NewPortStream : Creates stream level struct
func NewPortsStream() *PortsStream {
	srcPorts := make([]layers.TCPPort, 0)
	dstPorts := make([]layers.TCPPort, 0)

	return &PortsStream{srcPorts: srcPorts, dstPorts: dstPorts}
}

// AppendPorts : Append src and dst ports to their respective list
func (p *PortsStream) AppendPorts(srcPort, dstPort *layers.TCPPort) {
	p.srcPorts = append(p.srcPorts, *srcPort)
	p.dstPorts = append(p.dstPorts, *dstPort)
}

// GetData : Returns an array of ports for each packet in the format "srcPort->dstPort"
func (p *PortsStream) GetData() []string {
	ports := make([]string, 0)

	for i := range p.srcPorts {
		ports = append(ports, p.srcPorts[i].String()+"->"+p.dstPorts[i].String())
	}

	return ports
}

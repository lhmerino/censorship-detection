package net

import (
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger"
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger/data"
	"github.com/Kkevsterrr/gopacket"
	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/reassembly"
	"strconv"
)

// IPID : Config level struct
type IPID struct {
	// Inherits Collector Interface
	// Inherits ProcessPacketHeader Interface
}

// IPIDStream : Stream level struct
// - Array (representing each packet) of ipid
type IPIDStream struct {
	ipid []uint32
}

// ------ IPID Methods -----

// NewIPID : Creates the config level struct
func NewIPID() *IPID {
	return &IPID{}
}

// GetName : Description of this interface
func (p *IPID) GetName() string {
	return "[NET - IPID]"
}

// RelevantNewConnection : Relevant for IPv4 but only IPv6 when fragmenting
func (p *IPID) RelevantNewConnection(net gopacket.Flow, transport gopacket.Flow) bool {
	return true
}

// GetBasicInfo : No options available - return only its name
func (p *IPID) GetBasicInfo() string {
	return p.GetName()
}

// NewStream : Create stream level struct
func (p *IPID) NewStream(net, transport *gopacket.Flow, tcp *layers.TCP) interface{} {
	return NewIPIDStream()
}

// ProcessPacketHeader : Appends ipid for packet to TTLStream
func (p *IPID) ProcessPacketHeader(someInterface interface{}, packet *gopacket.Packet, tcp *layers.TCP,
	ci *gopacket.CaptureInfo, dir *reassembly.TCPFlowDirection) {
	stream := someInterface.(*IPIDStream)

	var ipid uint32

	if (*packet).NetworkLayer().LayerType() == layers.LayerTypeIPv4 {
		ipv4Layer := (*packet).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		ipid = uint32(ipv4Layer.Id)
	} else if (*packet).NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
		ipid = 1001 // Default value
		for _, layer := range (*packet).Layers() {
			if layer.LayerType() == layers.LayerTypeIPv6Fragment {
				ipv6FragmentLayer := (*packet).Layer(layers.LayerTypeIPv4).(*layers.IPv6Fragment)
				ipid = ipv6FragmentLayer.Identification
			}
		}
	} else {
		logger.Logger.Info("Unknown Network Layer: %s", (*packet).NetworkLayer().LayerType().String())
	}

	stream.Append(ipid)
}

// GetData : Returns array (each packet) of ttls
func (p *IPID) GetData(someInterface interface{}) *data.Array {
	stream := someInterface.(*IPIDStream)

	value := stream.GetData()

	return data.NewArray(p.GetName(), value)
}

// ----- IPID Stream Methods -----

// NewIPIDStream : Creates stream level struct
func NewIPIDStream() *IPIDStream {
	ipid := make([]uint32, 0)

	return &IPIDStream{ipid: ipid}
}

// Append : Appends ipid
func (p *IPIDStream) Append(ipid uint32) {
	p.ipid = append(p.ipid, ipid)
}

// GetData : Returns an array (representing each packet) of their ipid
func (p *IPIDStream) GetData() []string {
	ipidString := make([]string, len(p.ipid))

	for i, _ := range p.ipid {
		ipidString[i] = strconv.Itoa(int(p.ipid[i]))
	}

	return ipidString
}

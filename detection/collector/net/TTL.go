package net

import (
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger"
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger/data"
	"github.com/Kkevsterrr/gopacket"
	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/reassembly"
	"strconv"
)

// TTL : Config level struct
type TTL struct {
	// Inherits Collector Interface
	// Inherits ProcessPacketHeader Interface
}

// TTLStream : Stream level struct
// - Array (representing each packet) of ttls
type TTLStream struct {
	ttl []uint8
}

// ------ TTL Methods -----

// NewTTL : Creates the config level struct
func NewTTL() *TTL {
	return &TTL{}
}

// GetName : Description of this interface
func (p *TTL) GetName() string {
	return "[NET - TTL]"
}

// RelevantNewConnection : Relevant for both Network Layers IPv4 (TTL) and IPv6 (Hop Limit)
func (p *TTL) RelevantNewConnection(net gopacket.Flow, transport gopacket.Flow) bool {
	return true
}

// GetBasicInfo : No options available - return only its name
func (p *TTL) GetBasicInfo() string {
	return p.GetName()
}

// NewStream : Create stream level struct
func (p *TTL) NewStream(net, transport *gopacket.Flow, tcp *layers.TCP) interface{} {
	return NewTTLStream()
}

// ProcessPacketHeader : Appends ttl for packet to TTLStream
func (p *TTL) ProcessPacketHeader(someInterface interface{}, packet *gopacket.Packet, tcp *layers.TCP,
	ci *gopacket.CaptureInfo, dir *reassembly.TCPFlowDirection) {
	stream := someInterface.(*TTLStream)

	var ttl uint8

	if (*packet).NetworkLayer().LayerType() == layers.LayerTypeIPv4 {
		ipv4Layer := (*packet).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		ttl = ipv4Layer.TTL
	} else if (*packet).NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
		ipv6Layer := (*packet).Layer(layers.LayerTypeIPv4).(*layers.IPv6)
		ttl = ipv6Layer.HopLimit
	} else {
		logger.Logger.Info("Unknown Network Layer: %s", (*packet).NetworkLayer().LayerType().String())
		ttl = 0
	}

	stream.Append(ttl)
}

// GetData : Returns array (each packet) of ttls
func (p *TTL) GetData(someInterface interface{}) *data.Array {
	stream := someInterface.(*TTLStream)

	value := stream.GetData()

	return data.NewArray(p.GetName(), value)
}

// ----- TTL Stream Methods -----

// NewTTLStream : Creates stream level struct
func NewTTLStream() *TTLStream {
	ttl := make([]uint8, 0)

	return &TTLStream{ttl: ttl}
}

// Append : Appends ttl
func (p *TTLStream) Append(ttl uint8) {
	p.ttl = append(p.ttl, ttl)
}

// GetData : Returns an array (representing each packet) of their ttl
func (p *TTLStream) GetData() []string {
	ttlString := make([]string, len(p.ttl))

	for i := range p.ttl {
		ttlString[i] = strconv.Itoa(int(p.ttl[i]))
	}

	return ttlString
}

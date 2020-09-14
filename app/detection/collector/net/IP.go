package net

import (
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger/data"
	"github.com/Kkevsterrr/gopacket"
	"github.com/Kkevsterrr/gopacket/layers"
)


// IP : Config level struct for IP addresses capture
type IP struct {
	// Inherits Stream Interface
	// Inherits Collector Interface
}

// IPStream : Stream level struct for IP addresses capture
type IPStream struct {
	net gopacket.Flow // IP Endpoints
}


// ------ Basic Methods -------

// NewIP : Creates the config level struct
func NewIP() *IP {
	return &IP{}
}

// NewStream : Creates a IPStream struct for the stream
func (b *IP) NewStream(net, transport *gopacket.Flow, tcp *layers.TCP) interface {} {
	return NewIPStream(net)
}

// GetName : Description of this interface
func (b *IP) GetName() string {
	return "[Net - IP]"
}

// RelevantNewConnection :
//	All packets have IP headers so must always be relevant
func (b *IP) RelevantNewConnection(net, transport gopacket.Flow) bool {
	return true
}

// GetBasicInfo : No options available - return only its name
func (b *IP) GetBasicInfo() string {
	return b.GetName()
}

// GetData : Returns with only one value in the array. For memory efficiency,
//	use transport layer ports to determine direction of the packet.
func (b *IP) GetData(someInterface interface{}) *data.Array {
	ipStream := someInterface.(*IPStream)

	value := []string{ipStream.net.String()}

	return data.NewArray(b.GetName(), value)
}

// ------ Basic Stream Methods -------

// NewIPStream : Creates an IPStream that stores the two IP endpoints
func NewIPStream(net *gopacket.Flow) *IPStream {
	return &IPStream{net: *net}
}
package fingerprint

import (
	"breakerspace.cs.umd.edu/censorship/measurement/utils/bits"
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

type RSTACKs struct {
	Fingerprint
	Flags uint8 // 1111 11XX (two unused bits)
}

func NewRSTACKs() *RSTACKs {
	return &RSTACKs{Flags: 0}
}

func (c *RSTACKs) ProcessPacket(tcp *layers.TCP, ci gopacket.CaptureInfo,
	dir reassembly.TCPFlowDirection) {
	logger.Debug("Before Flags: %d\n", c.Flags)
	if tcp.PSH {
		c.Flags = bits.SetBit8(c.Flags, 0)
	} else if tcp.RST && tcp.ACK && !bits.HasBit8(c.Flags, 1) {
		c.Flags = bits.SetBit8(c.Flags, 1)
	} else if tcp.RST && tcp.ACK && !bits.HasBit8(c.Flags, 2) {
		c.Flags = bits.SetBit8(c.Flags, 2)
	} else if tcp.RST && tcp.ACK && !bits.HasBit8(c.Flags, 3) {
		c.Flags = bits.SetBit8(c.Flags, 3)
	} else if tcp.RST && !bits.HasBit8(c.Flags, 4) {
		c.Flags = bits.SetBit8(c.Flags, 4)
	} else if tcp.RST && !bits.HasBit8(c.Flags, 5) {
		c.Flags = bits.SetBit8(c.Flags, 5)
	}
	logger.Debug("After Flags: %d\n", c.Flags)
}

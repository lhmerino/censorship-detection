package fingerprint

import (
	"breakerspace.cs.umd.edu/censorship/measurement/utils/bits"
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

func (r *RSTACKs) ProcessPacket(tcp *layers.TCP, ci gopacket.CaptureInfo,
	dir reassembly.TCPFlowDirection) {
	r.flagsUpdate(tcp)
}

func (r *RSTACKs) CensorshipTriggered() bool {
	if bits.HasBit8(r.Flags, 0) && // PSH
		bits.HasBit8(r.Flags, 1) && // First RST-ACK
		bits.HasBit8(r.Flags, 2) && // Second RST-ACK
		bits.HasBit8(r.Flags, 4) {
		return true
	}

	return false
}

func (r *RSTACKs) flagsUpdate(tcp *layers.TCP) {
	if tcp.PSH {
		r.Flags = bits.SetBit8(r.Flags, 0)
	} else if tcp.RST && tcp.ACK && !bits.HasBit8(r.Flags, 1) {
		r.Flags = bits.SetBit8(r.Flags, 1)
	} else if tcp.RST && tcp.ACK && !bits.HasBit8(r.Flags, 2) {
		r.Flags = bits.SetBit8(r.Flags, 2)
	} else if tcp.RST && tcp.ACK && !bits.HasBit8(r.Flags, 3) {
		r.Flags = bits.SetBit8(r.Flags, 3)
	} else if tcp.RST && !tcp.ACK && !bits.HasBit8(r.Flags, 4) {
		r.Flags = bits.SetBit8(r.Flags, 4)
	} else if tcp.RST && !tcp.ACK && !bits.HasBit8(r.Flags, 5) {
		r.Flags = bits.SetBit8(r.Flags, 5)
	}
}

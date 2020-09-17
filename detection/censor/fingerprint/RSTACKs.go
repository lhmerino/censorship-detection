package fingerprint

import (
	"breakerspace.cs.umd.edu/censorship/measurement/utils/bits"
	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/reassembly"
)

type RSTACKs struct {
	Flags     uint8 // 1111 11XX (two unused bits)
	Direction bool
}

func NewRSTACKs(direction bool) *RSTACKs {
	return &RSTACKs{Flags: 0, Direction: direction}
}

func (r *RSTACKs) ProcessPacket(tcp *layers.TCP, dir *reassembly.TCPFlowDirection) {
	r.flagsUpdate(tcp, dir)
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

func (r *RSTACKs) flagsUpdate(tcp *layers.TCP, dir *reassembly.TCPFlowDirection) {
	if tcp.PSH &&
		(*dir == reassembly.TCPDirClientToServer || !r.Direction) {
		r.Flags = bits.SetBit8(r.Flags, 0)
	} else if tcp.RST && tcp.ACK && !bits.HasBit8(r.Flags, 1) &&
		(*dir == reassembly.TCPDirClientToServer || !r.Direction) {
		r.Flags = bits.SetBit8(r.Flags, 1)
	} else if tcp.RST && tcp.ACK && !bits.HasBit8(r.Flags, 2) &&
		(*dir == reassembly.TCPDirClientToServer || !r.Direction) {
		r.Flags = bits.SetBit8(r.Flags, 2)
	} else if tcp.RST && tcp.ACK && !bits.HasBit8(r.Flags, 3) &&
		(*dir == reassembly.TCPDirClientToServer || !r.Direction) {
		r.Flags = bits.SetBit8(r.Flags, 3)
	} else if tcp.RST && !tcp.ACK && !bits.HasBit8(r.Flags, 4) &&
		(*dir == reassembly.TCPDirClientToServer || !r.Direction) {
		r.Flags = bits.SetBit8(r.Flags, 4)
	} else if tcp.RST && !tcp.ACK && !bits.HasBit8(r.Flags, 5) &&
		(*dir == reassembly.TCPDirClientToServer || !r.Direction) {
		r.Flags = bits.SetBit8(r.Flags, 5)
	}
}

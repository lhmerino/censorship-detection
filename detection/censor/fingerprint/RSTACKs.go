package fingerprint

import (
	"breakerspace.cs.umd.edu/censorship/measurement/utils/bits"
	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/reassembly"
)

const (
	PSH = 0
	RSTACK1 = 1
	RSTACK2 = 2
	RSTACK3 = 3
	RST1 = 4
	RST2 = 5
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
	if bits.HasBit8(r.Flags, PSH) && // PSH
		bits.HasBit8(r.Flags, RSTACK1) && // First RST-ACK
		bits.HasBit8(r.Flags, RST1) { // First RST
		return true
	} else if bits.HasBit8(r.Flags, PSH) && // PSH
		bits.HasBit8(r.Flags, RSTACK1) && // First RST-ACK
		bits.HasBit8(r.Flags, RSTACK2) { // Second RST-ACK
		return true
	}

	return false
}

func (r *RSTACKs) flagsUpdate(tcp *layers.TCP, dir *reassembly.TCPFlowDirection) {
	if tcp.PSH &&
		(*dir == reassembly.TCPDirClientToServer || !r.Direction) {
		r.Flags = bits.SetBit8(r.Flags, PSH)
	} else if tcp.RST && tcp.ACK && !bits.HasBit8(r.Flags, RSTACK1) &&
		(*dir == reassembly.TCPDirClientToServer || !r.Direction) {
		r.Flags = bits.SetBit8(r.Flags, RSTACK1)
	} else if tcp.RST && tcp.ACK && !bits.HasBit8(r.Flags, RSTACK2) &&
		(*dir == reassembly.TCPDirClientToServer || !r.Direction) {
		r.Flags = bits.SetBit8(r.Flags, RSTACK2)
	} else if tcp.RST && tcp.ACK && !bits.HasBit8(r.Flags, RSTACK3) &&
		(*dir == reassembly.TCPDirClientToServer || !r.Direction) {
		r.Flags = bits.SetBit8(r.Flags, RSTACK3)
	} else if tcp.RST && !tcp.ACK && !bits.HasBit8(r.Flags, RST1) &&
		(*dir == reassembly.TCPDirClientToServer || !r.Direction) {
		r.Flags = bits.SetBit8(r.Flags, RST1)
	} else if tcp.RST && !tcp.ACK && !bits.HasBit8(r.Flags, RST2) &&
		(*dir == reassembly.TCPDirClientToServer || !r.Direction) {
		r.Flags = bits.SetBit8(r.Flags, RST2)
	}
}

package fingerprint

import (
	"breakerspace.cs.umd.edu/censorship/measurement/utils/bits"
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

type RSTACKs struct {
	Fingerprint
	Flags uint8 // 1111 11XX (two unused bits)
	Direction bool
}

func NewRSTACKs(direction bool) *RSTACKs {
	logger.Logger.Debug("[Fingerprint:RSTACK] Option[Direction]: %t", direction)
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
	logger.Logger.Debug("RSTACK: %d\n", r.Flags)
	if tcp.PSH &&
		(*dir == reassembly.TCPDirClientToServer || r.Direction == false) {
		r.Flags = bits.SetBit8(r.Flags, 0)
	} else if tcp.RST && tcp.ACK && !bits.HasBit8(r.Flags, 1) &&
		(*dir == reassembly.TCPDirClientToServer || r.Direction == false) {
		r.Flags = bits.SetBit8(r.Flags, 1)
	} else if tcp.RST && tcp.ACK && !bits.HasBit8(r.Flags, 2) &&
		(*dir == reassembly.TCPDirClientToServer || r.Direction == false) {
		r.Flags = bits.SetBit8(r.Flags, 2)
	} else if tcp.RST && tcp.ACK && !bits.HasBit8(r.Flags, 3) &&
		(*dir == reassembly.TCPDirClientToServer || r.Direction == false) {
		r.Flags = bits.SetBit8(r.Flags, 3)
	} else if tcp.RST && !tcp.ACK && !bits.HasBit8(r.Flags, 4) &&
		(*dir == reassembly.TCPDirClientToServer || r.Direction == false) {
		r.Flags = bits.SetBit8(r.Flags, 4)
	} else if tcp.RST && !tcp.ACK && !bits.HasBit8(r.Flags, 5) &&
		(*dir == reassembly.TCPDirClientToServer || r.Direction == false) {
		r.Flags = bits.SetBit8(r.Flags, 5)
	}
}

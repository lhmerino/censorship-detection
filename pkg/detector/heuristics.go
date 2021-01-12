package detector

import (
	"tripwire/pkg/util/bits"

	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/reassembly"
)

const (
	PSH     = 0
	RSTACK1 = 1
	RSTACK2 = 2
	RSTACK3 = 3
	RST1    = 4
	RST2    = 5
)

type rstAcks struct {
	flags uint8 // 1111 11XX (two unused bits)
}

func newRSTACKs() *rstAcks {
	return &rstAcks{}
}

func (r *rstAcks) processPacket(tcp *layers.TCP, dir reassembly.TCPFlowDirection) {
	if dir != reassembly.TCPDirClientToServer {
		return
	}
	if tcp.PSH {
		r.flags = bits.SetBit8(r.flags, PSH)
	} else if tcp.RST && tcp.ACK && !bits.HasBit8(r.flags, RSTACK1) {
		r.flags = bits.SetBit8(r.flags, RSTACK1)
	} else if tcp.RST && tcp.ACK && !bits.HasBit8(r.flags, RSTACK2) {
		r.flags = bits.SetBit8(r.flags, RSTACK2)
	} else if tcp.RST && tcp.ACK && !bits.HasBit8(r.flags, RSTACK3) {
		r.flags = bits.SetBit8(r.flags, RSTACK3)
	} else if tcp.RST && !tcp.ACK && !bits.HasBit8(r.flags, RST1) {
		r.flags = bits.SetBit8(r.flags, RST1)
	} else if tcp.RST && !tcp.ACK && !bits.HasBit8(r.flags, RST2) {
		r.flags = bits.SetBit8(r.flags, RST2)
	}
}

func (r *rstAcks) detected() bool {
	if bits.HasBit8(r.flags, PSH) && // PSH
		bits.HasBit8(r.flags, RSTACK1) && // First RST-ACK
		bits.HasBit8(r.flags, RST1) { // First RST
		return true
	} else if bits.HasBit8(r.flags, PSH) && // PSH
		bits.HasBit8(r.flags, RSTACK1) && // First RST-ACK
		bits.HasBit8(r.flags, RSTACK2) { // Second RST-ACK
		return true
	}

	return false
}

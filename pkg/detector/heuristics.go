package detector

import (
	"tripwire/pkg/util/bits"

	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/reassembly"
)

### RST-ACK heuristic
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

### Heu
const (

)


const (
	W_PSH = 0
	W_WIN = 1
)

type window struct {
	flags uint8 // 11XX XXXX (two used bits)
}

func NewWindow() *window {
	return &window{}
}

func (h *window) processPacket(tcp *layers.TCP, dir reassembly.TCPFlowDirection) {
	if dir != reassembly.TCPDirClientToServer {
		return
	}

	if tcp.PSH {
		h.flags = bits.SetBit8(h.flags, W_PSH)
	} else if tcp.RST && tcp.Window == 16 {
		h.flags = bits.SetBit8(h.flags, W_WIN)
	}
}

func (h *window) detected() bool {
	if bits.HasBit8(h.flags, W_PSH) && // PSH
		bits.HasBit8(h.flags, W_WIN) {
		return true
	}

	return false
}
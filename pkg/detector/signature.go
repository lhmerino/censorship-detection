package detector

import (
	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/reassembly"
)

// RST--RST-ACK signature, exhibited by the GFW (China)
// https://conferences.sigcomm.org/imc/2017/papers/imc17-final59.pdf
type rstacksSignature struct {
	PSH, RSTACK1, RSTACK2, RSTACK3, RST1, RST2 bool
}

func newRSTACKsSignature() *rstacksSignature {
	return &rstacksSignature{}
}

func (r *rstacksSignature) processPacket(tcp *layers.TCP, dir reassembly.TCPFlowDirection) {
	if dir != reassembly.TCPDirClientToServer {
		return
	}
	if tcp.PSH {
		r.PSH = true
	} else if tcp.RST && tcp.ACK && !r.RSTACK1 {
		r.RSTACK1 = true
	} else if tcp.RST && tcp.ACK && !r.RSTACK2 {
		r.RSTACK2 = true
	} else if tcp.RST && tcp.ACK && !r.RSTACK3 {
		r.RSTACK3 = true
	} else if tcp.RST && !tcp.ACK && !r.RST1 {
		r.RST1 = true
	} else if tcp.RST && !tcp.ACK && !r.RST2 {
		r.RST2 = true
	}
}

func (r *rstacksSignature) detected() bool {
	return (r.PSH && r.RSTACK1 && r.RST1) ||
		(r.PSH && r.RSTACK1 && r.RSTACK2)
}

// WIN signature, exhibited by Airtel (India)
// See testdata/airtel_example.pcap and testdata/airtel_https_example.pcap.
type windowSignature struct {
	PSH, WIN bool
}

func newWindowSignature() *windowSignature {
	return &windowSignature{}
}

func (h *windowSignature) processPacket(tcp *layers.TCP, dir reassembly.TCPFlowDirection) {
	if dir != reassembly.TCPDirClientToServer {
		return
	}

	if tcp.PSH {
		h.PSH = true
	} else if tcp.RST && tcp.Window == 16 {
		h.WIN = true
	}
}

func (h *windowSignature) detected() bool {
	return h.PSH && h.WIN
}

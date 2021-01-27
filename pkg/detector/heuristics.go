package detector

import (
	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/reassembly"
)

// RST--RST-ACK heuristic, exhibited by the GFW (China)
// https://conferences.sigcomm.org/imc/2017/papers/imc17-final59.pdf
type rstacksHeuristic struct {
	PSH, RSTACK1, RSTACK2, RSTACK3, RST1, RST2 bool
}

func newRSTACKsHeuristic() *rstacksHeuristic {
	return &rstacksHeuristic{}
}

func (r *rstacksHeuristic) processPacket(tcp *layers.TCP, dir reassembly.TCPFlowDirection) {
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

func (r *rstacksHeuristic) detected() bool {
	return (r.PSH && r.RSTACK1 && r.RST1) ||
		(r.PSH && r.RSTACK1 && r.RSTACK2)
}

// WIN heuristic, exhibited by Airtel (India)
// See testdata/airtel_example.pcap and testdata/airtel_https_example.pcap.
type windowHeuristic struct {
	PSH, WIN bool
}

func newWindowHeuristic() *windowHeuristic {
	return &windowHeuristic{}
}

func (h *windowHeuristic) processPacket(tcp *layers.TCP, dir reassembly.TCPFlowDirection) {
	if dir != reassembly.TCPDirClientToServer {
		return
	}

	if tcp.PSH {
		h.PSH = true
	} else if tcp.RST && tcp.Window == 16 {
		h.WIN = true
	}
}

func (h *windowHeuristic) detected() bool {
	return h.PSH && h.WIN
}

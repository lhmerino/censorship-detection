package fingerprint

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

type Fingerprint interface {
	ProcessPacket(tcp *layers.TCP, ci gopacket.CaptureInfo,
		dir reassembly.TCPFlowDirection)
}

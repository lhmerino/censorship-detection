package fingerprint

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

type Fingerprint interface {
	/*
		Look for indications that this connection is being censored
	*/
	ProcessPacket(tcp *layers.TCP, ci gopacket.CaptureInfo,
		dir reassembly.TCPFlowDirection)

	/*
		Do we suspect that this connection has triggered the censor?
	*/
	CensorshipTriggered() bool
}

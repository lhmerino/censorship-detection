package fingerprint

import (
	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/reassembly"
)

type Fingerprint interface {
	/*
		Look for indications that this connection is being censored
	*/
	ProcessPacket(tcp *layers.TCP, dir *reassembly.TCPFlowDirection)

	/*
		Do we suspect that this connection has triggered the censor?
	*/
	CensorshipTriggered() bool
}

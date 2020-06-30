package fingerprint

import (
	"github.com/google/gopacket/layers"
)

type Fingerprint interface {
	/*
		Look for indications that this connection is being censored
	*/
	ProcessPacket(tcp *layers.TCP)

	/*
		Do we suspect that this connection has triggered the censor?
	*/
	CensorshipTriggered() bool
}

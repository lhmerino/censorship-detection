package censor

import (
	"breakerspace.cs.umd.edu/censorship/measurement/detection/fingerprint"
	"bytes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// China Fingerprint 1: 3 RSTACKs + 1 RST
// PUSH | 1st RSTACK | 2nd RSTACK | 3rd RSTACK | 4th RST | 5th RST
type China struct {
	Censor
}

func NewChina() *China {
	return &China{}
}

func (c *China) GetName() string {
	return "China"
}

func (c *China) RelevantNewConnection(net gopacket.Flow, transport gopacket.Flow) bool {
	return true
}

func (c *China) GetBasicInfo() string {
	return "China"
}

func (c *China) NewStream() interface{} {
	return fingerprint.NewRSTACKs()
}

func (c *China) ProcessPacket(someInterface interface{}, tcp *layers.TCP) {
	rstACKs := someInterface.(*fingerprint.RSTACKs)
	rstACKs.ProcessPacket(tcp)
}

func (c *China) DetectCensorship(someInterface interface{}, net *gopacket.Flow, transport *gopacket.Flow, content *bytes.Buffer) bool {
	rstACKs := someInterface.(*fingerprint.RSTACKs)
	if rstACKs.CensorshipTriggered() {
		return true
		//logger.Logger.Connection(net, transport, content)
	}
	return false
}

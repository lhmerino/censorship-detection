package censor

import (
	"breakerspace.cs.umd.edu/censorship/measurement/detection/fingerprint"
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger"
	"bytes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

// China Fingerprint 1: 3 RSTACKs + 1 RST
// PUSH | 1st RSTACK | 2nd RSTACK | 3rd RSTACK | 4th RST | 5th RST
type China struct {
	Censor

	streams map[string]*fingerprint.RSTACKs
	content map[string]bytes.Buffer
}

func NewChina() *China {
	return &China{streams: make(map[string]*fingerprint.RSTACKs)}
}

func (c *China) GetName() string {
	return "China"
}

func (c *China) RelevantNewConnection(net gopacket.Flow, transport gopacket.Flow) bool {
	return true
}

func (c *China) NewStream(ident *string) {
	c.streams[*ident] = fingerprint.NewRSTACKs()
}

func (c *China) ProcessPacket(ident *string, tcp *layers.TCP, ci gopacket.CaptureInfo,
	dir reassembly.TCPFlowDirection) {
	c.streams[*ident].ProcessPacket(tcp, ci, dir)

}

func (c *China) DetectCensorship(ident *string, net *gopacket.Flow, transport *gopacket.Flow, content *bytes.Buffer) {
	if c.streams[*ident].CensorshipTriggered() {
		logger.Logger.Connection(net, transport, content)
	}
}

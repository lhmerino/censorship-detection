package censor

import (
	"breakerspace.cs.umd.edu/censorship/measurement/config"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/censor/fingerprint"
	"github.com/Kkevsterrr/gopacket"
	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/reassembly"
)

// China Fingerprint 1: 3 RSTACKs + 1 RST
// PUSH | 1st RSTACK | 2nd RSTACK | 3rd RSTACK | 4th RST | 5th RST
type China struct {
	Censor

	Options *config.MeasurementOptions
}

// Data for each Stream
type ChinaStream struct {
	CensorshipDetected bool
	RSTACK *fingerprint.RSTACKs
}

func NewChina(options *config.MeasurementOptions) *China {
	return &China{Options: options}
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

func (c *China) NewStream(net, transport *gopacket.Flow, tcp *layers.TCP) interface{} {
	rstACK := fingerprint.NewRSTACKs(c.Options.Direction)

	return NewChinaStream(rstACK)
}

func (c *China) ProcessPacketHeader(someInterface interface{}, packet *gopacket.Packet, tcp *layers.TCP, ci *gopacket.CaptureInfo,
	dir *reassembly.TCPFlowDirection) {
	chinaStream := someInterface.(*ChinaStream)

	// Process Contents of Packet
	chinaStream.RSTACK.ProcessPacket(tcp, dir)
}

func (c *China) DetectCensorship(someInterface interface{}) uint8 {
	chinaStream := someInterface.(*ChinaStream)

	// Determine if censorship has been triggered for this stream (and censor)
	if chinaStream.RSTACK.CensorshipTriggered() {
		chinaStream.CensorshipDetected = true
		return DETECTED
	}

	return NOT_DETECTED
}

// --- China Stream Methods ---

func NewChinaStream(RSTACK *fingerprint.RSTACKs) *ChinaStream {
	return &ChinaStream{RSTACK: RSTACK, CensorshipDetected: false}
}

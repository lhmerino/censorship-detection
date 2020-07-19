package censor

import (
	"breakerspace.cs.umd.edu/censorship/measurement/config"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/censor/fingerprint"
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
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

func NewChinaStream(RSTACK *fingerprint.RSTACKs) *ChinaStream {
	return &ChinaStream{RSTACK: RSTACK, CensorshipDetected: false}
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

func (c *China) NewStream() interface{} {
	logger.Logger.Debug("[Censor:China:New Stream] Function Call")
	rstACK := fingerprint.NewRSTACKs(c.Options.Direction)
	return NewChinaStream(rstACK)

}

func (c *China) ProcessPacket(someInterface interface{}, tcp *layers.TCP, ci *gopacket.CaptureInfo,
	dir *reassembly.TCPFlowDirection) {
	logger.Logger.Debug("[Censor:China:Accept] Function Call")
	chinaStream := someInterface.(*ChinaStream)

	// Process Contents of Packet
	chinaStream.RSTACK.ProcessPacket(tcp, dir)
}

func (c *China) DetectCensorship(someInterface interface{}) uint8 {//, net *gopacket.Flow, transport *gopacket.Flow, content *bytes.Buffer) bool {
	chinaStream := someInterface.(*ChinaStream)

	// Check if censorship has already been triggered for this censor
	if chinaStream.CensorshipDetected == true {
		return OLD_DETECTED
	}

	// Determine if censorship has been triggered for this stream (and censor)
	if chinaStream.RSTACK.CensorshipTriggered() {
		chinaStream.CensorshipDetected = true
		return NEW_DETECTED
	}

	return NOT_DETECTED
}

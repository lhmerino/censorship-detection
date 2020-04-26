package censor

import (
	"breakerspace.cs.umd.edu/censorship/measurement/detection/shared"
	"bytes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

type Censor interface {
	shared.SharedInterface

	NewStream(ident *string)

	ProcessPacket(ident *string, tcp *layers.TCP, ci gopacket.CaptureInfo,
		dir reassembly.TCPFlowDirection)

	DetectCensorship(ident *string, net *gopacket.Flow, transport *gopacket.Flow, content *bytes.Buffer)
}
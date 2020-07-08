package censor

import (
	"breakerspace.cs.umd.edu/censorship/measurement/detection/shared"
	"bytes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Censor interface {
	shared.SharedInterface

	NewStream() interface{}

	ProcessPacket(someInterface interface{}, tcp *layers.TCP)

	DetectCensorship(someInterface interface{}, net *gopacket.Flow, transport *gopacket.Flow, content *bytes.Buffer) bool
}

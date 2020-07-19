package censor

import (
	"breakerspace.cs.umd.edu/censorship/measurement/detection/shared"
)

const NOT_DETECTED = 0
const NEW_DETECTED = 1
const OLD_DETECTED = 2

type Censor interface {
	shared.MainInterface
	shared.ProcessPacketInterface

	NewStream() interface{}

	DetectCensorship(someInterface interface{}) uint8
}

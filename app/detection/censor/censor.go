package censor

import (
	"breakerspace.cs.umd.edu/censorship/measurement/detection/shared"
)


// NOT_DETECTED Constant signifying that the censor's
// action(s) have not been detected in this stream
const NOT_DETECTED = 0

// NEW_DETECTED Constant signifying that censorship by this censor
// has _just_ (given the last processed packet) been detected
const NEW_DETECTED = 1

// DETECTED Constant signifying that this stream is considered censored
const DETECTED = 2

// Censor :
// 	A representation of one particular censor.
//	Each packet is processed by the censor to detect whether
//	the stream has been censored by that particular censor.
//
type Censor interface {
	shared.MainInterface
	shared.ProcessPacketInterface

	NewStream() interface{}

	// Returns whether the censor has detected censorship
	// using one of the constants specified above
	DetectCensorship(someInterface interface{}) uint8
}

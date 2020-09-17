package censor

import (
	"breakerspace.cs.umd.edu/censorship/measurement/config"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/shared"
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger"
	"os"
)

// NOT_DETECTED Constant signifying that the censor's
// action(s) have not been detected in this stream
const NOT_DETECTED = 0

// DETECTED Constant signifying that this stream is considered censored
const DETECTED = 1

// Censor :
// 	A representation of one particular censor.
//	Each packet is processed by the censor to detect whether
//	the stream has been censored by that particular censor.
//
type Censor interface {
	shared.MainInterface
	shared.StreamInterface
	shared.ProcessPacketHeaderInterface

	// Returns whether the censor has detected censorship
	// using one of the constants specified above
	DetectCensorship(someInterface interface{}) uint8
}

// ReadCensorFromMeasurementConfig :
//	Returns the censor implementation given the string value
//	specified in the measurement definition in the YAML file
func ReadCensorFromMeasurementConfig(measurement *config.MeasurementConfig) Censor {
	if measurement.Censor == "China" {
		return NewChina(&measurement.Options)
	}

	logger.Logger.Error("[Config] Invalid Measurement Censor %s\n", measurement.Censor)
	os.Exit(1)
	return nil
}

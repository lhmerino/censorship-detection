package protocol

import (
	"breakerspace.cs.umd.edu/censorship/measurement/config"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/shared"
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger"
	"os"
)

type Protocol interface {
	shared.MainInterface

	// BPF filter for protocol
	GetBPFFilter() string

	GetPort() uint16
}

// ReadProtocolFromMeasurementConfig :
//	Returns the protocol implementation given the string value
//	specified in the measurement definition in the YAML file
func ReadProtocolFromMeasurementConfig(measurement *config.MeasurementConfig) Protocol {
	// Protocols
	switch measurement.Protocol {
	case "HTTP":
		return NewHTTP(measurement.Port)
	case "DNS":
		return NewDNS(measurement.Port)
	case "HTTPS":
		return NewHTTPS(measurement.Port)
	case "SMTP":
		return NewSMTP(measurement.Port)
	}

	logger.Logger.Error(measurement.Protocol)
	logger.Logger.Error("[Config] Invalid Measurement Protocol %s\n", measurement.Protocol)
	os.Exit(1)
	return nil
}

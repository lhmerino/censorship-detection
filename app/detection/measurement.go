package detection

import (
	"breakerspace.cs.umd.edu/censorship/measurement/config"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/censor"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/protocol"
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger"
	"github.com/Kkevsterrr/gopacket"
	"os"
)

//Measurement :
//	Composed of a specific Protocol, a specific Censor and Options
type Measurement struct {
	//Interface
	Censor   *censor.Censor
	Protocol *protocol.Protocol

	// Options
	Options *config.MeasurementOptions
}


var Measurements []*Measurement

//type stats struct {
//	ipdefrag            int
//	missedBytes         int
//	pkt                 int
//	sz                  int
//	totalsz             int
//	rejectFsm           int
//	rejectOpt           int
//	rejectConnFsm       int
//	reassembled         int
//	outOfOrderBytes     int
//	outOfOrderPackets   int
//	biggestChunkBytes   int
//	biggestChunkPackets int
//	overlapBytes        int
//	overlapPackets      int
//}


func NewMeasurement(censor *censor.Censor, protocol *protocol.Protocol, options *config.MeasurementOptions) *Measurement {
	return &Measurement{Censor: censor, Protocol: protocol, Options: options}
}

// SetupMeasurements :
//	Dynamic Measurement Setup based on YAML config file
func SetupMeasurements(cfg *[]config.MeasurementConfig) {
	Measurements = make([]*Measurement, len(*cfg))
	for i, _ := range *cfg {
		protocolVar := ReadProtocolFromMeasurementConfig(&(*cfg)[i])
		censorVar := ReadCensorFromMeasurementConfig(&(*cfg)[i])

		Measurements[i] = NewMeasurement(&censorVar, &protocolVar, &(*cfg)[i].Options)
	}
}

// ReadProtocolFromMeasurementConfig :
//	Returns the protocol implementation given the string value
//	specified in the measurement definition in the YAML file
func ReadProtocolFromMeasurementConfig(measurement *config.MeasurementConfig) protocol.Protocol {
	// Protocols
	if measurement.Protocol == "HTTP" {
		return protocol.NewHTTPCustom(measurement.Port)
	}
	logger.Logger.Error(measurement.Protocol)
	logger.Logger.Error("[Config] Invalid Measurement Protocol %s\n", measurement.Protocol)
	os.Exit(1)
	return nil
}

// ReadCensorFromMeasurementConfig :
//	Returns the censor implementation given the string value
//	specified in the measurement definition in the YAML file
func ReadCensorFromMeasurementConfig(measurement *config.MeasurementConfig) censor.Censor {
	if measurement.Censor == "China" {
		return censor.NewChina(&measurement.Options)
	}

	logger.Logger.Error("[Config] Invalid Measurement Censor %s\n", measurement.Censor)
	os.Exit(1)
	return nil
}

func GetBPFFilters(measurements []*Measurement) string {
	filter := ""
	measurementsLength := len(measurements)
	for i := 0; i < measurementsLength; i++ {
		if i != measurementsLength-1 {
			filter += "(" + (*measurements[i].Protocol).GetBPFFilter() + ") or "
		} else {
			filter += "(" + (*measurements[i].Protocol).GetBPFFilter() + ")"
		}
	}

	return filter
}

/*
	Determine which application protocol should be run
	for this stream.
*/
func RelevantNewConnection(measurements []*Measurement,
	net gopacket.Flow, transport gopacket.Flow) []*Measurement {
	var applicableMeasurements []*Measurement
	for i := 0; i < len(measurements); i++ {
		if (*measurements[i].Protocol).RelevantNewConnection(net, transport) &&
			(*measurements[i].Censor).RelevantNewConnection(net, transport) {
			applicableMeasurements = append(applicableMeasurements, measurements[i])
		}
	}

	return applicableMeasurements
}

func GetBasicInfo(measurements []*Measurement) string {
	basicInfo := ""
	measurementsLength := len(measurements)
	for i := 0; i < measurementsLength; i++ {
		if i != measurementsLength-1 {
			basicInfo += (*measurements[i].Censor).GetBasicInfo() + "/"
			basicInfo += (*measurements[i].Protocol).GetBasicInfo() + " & "
		} else {
			basicInfo += (*measurements[i].Censor).GetBasicInfo() + "/"
			basicInfo += (*measurements[i].Protocol).GetBasicInfo()
		}
	}
	return basicInfo
}

package detection

import (
	"breakerspace.cs.umd.edu/censorship/measurement/config"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/censor"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/protocol"
	"github.com/google/gopacket"
)

//Measurement contains a specific Protocol and a specific Censor
type Measurement struct {
	//Interface
	Censor   *censor.Censor
	Protocol *protocol.Protocol

	// Protocol Options
	Port int
}

var Measurements []*Measurement

type stats struct {
	ipdefrag            int
	missedBytes         int
	pkt                 int
	sz                  int
	totalsz             int
	rejectFsm           int
	rejectOpt           int
	rejectConnFsm       int
	reassembled         int
	outOfOrderBytes     int
	outOfOrderPackets   int
	biggestChunkBytes   int
	biggestChunkPackets int
	overlapBytes        int
	overlapPackets      int
}


func NewMeasurement(censor censor.Censor, protocol protocol.Protocol) *Measurement {
	return &Measurement{Censor: &censor, Protocol: &protocol}
}

/**
	Needs to be made dynamic
 */
func SetupMeasurements(cfg *config.Config) {

	Measurements = make([]*Measurement, 1)

	protocolVar9999 := protocol.NewHTTPCustom(uint16(cfg.Protocol.HTTP.Port))
	censorVar := censor.NewChina()
	Measurements[0] = NewMeasurement(censorVar, protocolVar9999)

	//protocolVar8888 := protocol.NewHTTPCustom(8888)
	//detection.Measurements[1] = detection.NewMeasurement(censorVar, protocolVar8888)
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
	var measurementsApply []*Measurement
	for i := 0; i < len(measurements); i++ {
		if (*measurements[i].Protocol).RelevantNewConnection(net, transport) &&
			(*measurements[i].Censor).RelevantNewConnection(net, transport) {
			measurementsApply = append(measurementsApply, measurements[i])
		}
	}

	return measurementsApply
}

func GetBasicInfo(measurements []*Measurement) string {
	basicInfo := ""
	measurementsLength := len(measurements)
	for i := 0; i < measurementsLength; i++ {
		if i != measurementsLength-1 {
			basicInfo += (*measurements[i].Protocol).GetBasicInfo() + " & "
		} else {
			basicInfo += (*measurements[i].Protocol).GetBasicInfo()
		}
	}
	return basicInfo
}

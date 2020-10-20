package detection

import (
	"breakerspace.cs.umd.edu/censorship/measurement/config"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/censor"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/protocol"
	"fmt"
	"github.com/Kkevsterrr/gopacket"
	"github.com/prometheus/client_golang/prometheus"
)

//Measurement :
//	Composed of a specific Protocol, a specific Censor and Options
type Measurement struct {
	//Interface
	Censor   *censor.Censor
	Protocol *protocol.Protocol

	// Options
	Options *config.MeasurementOptions

	// Metrics
	StreamsCount          prometheus.Counter
	DisruptedStreamsCount prometheus.Counter
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
	measurement := &Measurement{Censor: censor, Protocol: protocol, Options: options}

	name := fmt.Sprintf("%v_%v_%v", len(Measurements), (*measurement.Censor).GetName(), (*measurement.Protocol).GetName())

	measurement.StreamsCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: name,
		Help: "Number of streams observed for " + name + ".",
	})

	measurement.DisruptedStreamsCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: name,
		Help: "Number of disrupted streams observed for " + name + ".",
	})

	return measurement
}

// SetupMeasurements :
//	Dynamic Measurement Setup based on YAML config file
func SetupMeasurements(cfg *[]config.MeasurementConfig) {
	Measurements = make([]*Measurement, len(*cfg))
	for i := range *cfg {
		protocolVar := protocol.ReadProtocolFromMeasurementConfig(&(*cfg)[i])
		censorVar := censor.ReadCensorFromMeasurementConfig(&(*cfg)[i])

		Measurements[i] = NewMeasurement(&censorVar, &protocolVar, &(*cfg)[i].Options)
	}
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

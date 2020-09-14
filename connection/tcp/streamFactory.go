package tcp

import (
	"breakerspace.cs.umd.edu/censorship/measurement/detection"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/collector"
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger"
	"github.com/Kkevsterrr/gopacket"
	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/reassembly"
)

type StreamFactory struct {
	options *Options
}

func NewStreamFactory(options *Options) *StreamFactory {
	return &StreamFactory{options: options}
}

func (factory *StreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	logger.Logger.Info("** NEW Connection: %s %s", net, transport)

	applicableMeasurements := detection.RelevantNewConnection(detection.Measurements, net, transport)
	logger.Logger.Debug("%s %s: Relevant Measurements: %s", net, transport, detection.GetBasicInfo(applicableMeasurements))

	applicableCollectors := collector.RelevantNewConnection(collector.Collectors, net, transport)
	logger.Logger.Debug("%s %s: Relevant Collectors: %s", net, transport, collector.GetBasicInfo(applicableCollectors))

	// Create Stream struct with applicable measurements and data collectors
	stream := &Stream{
		net:       net,
		transport: transport,

		measurements: applicableMeasurements,
		collectors: applicableCollectors,
	}

	// Create state for each relevant measurement
	stream.measurementStorage = make(map[int]interface{})
	for i := 0; i < len(stream.measurements); i++ {
		stream.measurementStorage[i] = (*applicableMeasurements[i].Censor).NewStream(&net, &transport, tcp)
	}

	// Create state for each relevant collector
	stream.collectorStorage = make(map[int]interface{})
	for i := 0; i < len(stream.collectors); i++ {
		stream.collectorStorage[i] = applicableCollectors[i].NewStream(&net, &transport, tcp)
	}

	return stream
}

package tcp

import (
	"breakerspace.cs.umd.edu/censorship/measurement/detection"
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
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
	logger.Logger.Debug("%s %s: %s", net, transport, detection.GetBasicInfo(applicableMeasurements))

	// TCP Finite State Machine Options
	fsmOptions := reassembly.TCPSimpleFSMOptions{
		// Allow missing TCP handshake?
		SupportMissingEstablishment: *factory.options.allowMissingInit,
	}

	// Create Stream
	stream := &Stream{
		net:        net,
		transport:  transport,
		tcpstate:   reassembly.NewTCPSimpleFSM(fsmOptions),
		ident:      fmt.Sprintf("%s:%s", net, transport),
		optchecker: reassembly.NewTCPOptionCheck(),

		measurements: applicableMeasurements,
	}

	// Create state for each relevant measurement
	for i := 0; i < len(applicableMeasurements); i++ {
		//ident := make([]byte, len(stream.ident))
		(*applicableMeasurements[i].Censor).NewStream(&stream.ident)
	}

	return stream
}

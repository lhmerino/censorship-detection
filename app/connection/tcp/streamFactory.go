package tcp

import (
	"breakerspace.cs.umd.edu/censorship/measurement/detection"
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"sync"
)

type StreamFactory struct {
	wg      sync.WaitGroup
	options *Options
}

func NewStreamFactory(options *Options) *StreamFactory {
	return &StreamFactory{options: options}
}

func (factory *StreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	logger.Info("** NEW Connection: %s %s\n", net, transport)

	applicableMeasurements := detection.RelevantNewConnection(detection.Measurements, net, transport)
	logger.Debug(detection.GetBasicInfo(applicableMeasurements))

	// TCP Finite State Machine Options
	fsmOptions := reassembly.TCPSimpleFSMOptions{
		// Allow missing TCP handshake?
		SupportMissingEstablishment: *factory.options.allowMissingInit,
	}

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

	//if true {
	/*stream.client = protocol.HttpReader{
		Bytes: make(chan []byte),
		Ident: fmt.Sprintf("%s %s", net, transport),
		//Hexdump:  *factory.options,
		IsClient: true,
	}*/
	/*stream.server = httpReader{
		bytes:   make(chan []byte),
		ident:   fmt.Sprintf("%s %s", net.Reverse(), transport.Reverse()),
		hexdump: *hexdump,
		parent:  stream,
	}*/
	//factory.wg.Add(1)
	//go stream.client.Run(&factory.wg)
	//go stream.server.run(&factory.wg) <- Server unecessary for now
	//}
	return stream
}

func (factory *StreamFactory) WaitGoRoutines() {
	factory.wg.Wait()
}

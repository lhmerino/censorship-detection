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
	wg          sync.WaitGroup
	options     *Options
	measurement *detection.Measurement
}

func NewStreamFactory(options *Options, measurement *detection.Measurement) *StreamFactory {
	return &StreamFactory{options: options, measurement: measurement}
}

func (factory *StreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	logger.Info("* NEW Connection: %s %s\n", net, transport)

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

		measurement: factory.measurement,
	}
	if true {
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
	}
	return stream
}

func (factory *StreamFactory) WaitGoRoutines() {
	factory.wg.Wait()
}

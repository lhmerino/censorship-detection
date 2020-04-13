package tcp

import (
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"sync"
)

type StreamFactory struct {
	wg      sync.WaitGroup
	doHTTP  bool
	options *Options
}

func NewStreamFactory(options *Options) *StreamFactory {
	return &StreamFactory{options: options}
}

func (factory *StreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	logger.Debug("* NEW Connection: %s %s\n", net, transport)

	// TCP Finite State Machine Options
	fsmOptions := reassembly.TCPSimpleFSMOptions{
		// Allow missing TCP handshake?
		SupportMissingEstablishment: *factory.options.allowMissingInit,
	}

	factory.doHTTP = true
	stream := &Stream{
		net:        net,
		transport:  transport,
		isDNS:      tcp.SrcPort == 53 || tcp.DstPort == 53,
		isHTTP:     (tcp.SrcPort == 80 || tcp.DstPort == 9999) && factory.doHTTP,
		reversed:   tcp.SrcPort == 80,
		tcpstate:   reassembly.NewTCPSimpleFSM(fsmOptions),
		ident:      fmt.Sprintf("%s:%s", net, transport),
		optchecker: reassembly.NewTCPOptionCheck(),
	}
	if stream.isHTTP {
		/*stream.client = httpReader{
			bytes:    make(chan []byte),
			ident:    fmt.Sprintf("%s %s", net, transport),
			hexdump:  *hexdump,
			parent:   stream,
			isClient: true,
		}
		/*stream.server = httpReader{
			bytes:   make(chan []byte),
			ident:   fmt.Sprintf("%s %s", net.Reverse(), transport.Reverse()),
			hexdump: *hexdump,
			parent:  stream,
		}
		factory.wg.Add(1)
		go stream.client.run(&factory.wg)*/
		//go stream.server.run(&factory.wg) <- Server unecessary for now
	}
	return stream
}

func (factory *StreamFactory) WaitGoRoutines() {
	/*factory.wg.Wait()*/
}

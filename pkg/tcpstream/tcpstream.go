package tcpstream

import (
	"fmt"
	"strconv"
	"sync"

	"tripwire/pkg/collector"
	"tripwire/pkg/config"
	"tripwire/pkg/detector"
	"tripwire/pkg/logger"

	"github.com/Kkevsterrr/gopacket"
	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/reassembly"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	StreamsCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tripwire_streams_count",
			Help: "Number of streams observed.",
		},
		[]string{"detector", "disrupted"},
	)
)

// tcpStreamFactory implements reassembly.StreamFactory
// https://godoc.org/github.com/Kkevsterrr/gopacket/reassembly#StreamFactory
type tcpStreamFactory struct {
	allowMissingInit  bool // Allow for creating flows without actual TCP handshake
	maxPacketCount    int  // Maximum number of packets to accept from each of the client and server
	detectorFactories []detector.DetectorFactory
	collectorFactory  collector.CollectorFactory
	streamWriter      func(detector []detector.Detector, collector collector.Collector)
}

// tcpStream implements reassembly.Stream
// https://godoc.org/github.com/Kkevsterrr/gopacket/reassembly#Stream
type tcpStream struct {
	// Parties in this connection
	// (net with transport = stream unique identifier)
	net, transport gopacket.Flow
	// Whether or not the flow client and server should be reversed
	reversed bool
	// Whether or not streams missinginit (syn-syn/ack-ack) should be retained
	allowMissingInit bool
	SYN              bool

	// Number of packets sent by the client and server
	maxPacketCount, clientPacketCount, serverPacketCount int

	detectors    []detector.Detector
	collector    collector.Collector
	streamWriter func(detector []detector.Detector, collector collector.Collector)

	sync.Mutex
}

func NewTCPStreamFactory(cfg config.TCPConfig, cf collector.CollectorFactory, dfs []detector.DetectorFactory,
	streamWriter func(detector []detector.Detector, collector collector.Collector)) *tcpStreamFactory {
	maxPacketCount := cfg.MaxPacketCount
	if maxPacketCount == 0 {
		maxPacketCount = 25
	}
	return &tcpStreamFactory{
		allowMissingInit:  cfg.AllowMissingInit,
		maxPacketCount:    maxPacketCount,
		collectorFactory:  cf,
		detectorFactories: dfs,
		streamWriter:      streamWriter,
	}
}

func (f *tcpStreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	logger.Debug.Printf("%s %s: New Connection", net, transport)

	var detectors []detector.Detector
	var reversed bool
	for _, df := range f.detectorFactories {
		if df.RelevantToConnection(net, transport) {
			detectors = append(detectors, df.NewDetector(net, transport, tcp))
		}
	}
	if len(detectors) == 0 {
		// The stream wasn't relevant to any detectors, so try in the reverse direction.
		reversed = true
		net = net.Reverse()
		transport = transport.Reverse()
		for _, df := range f.detectorFactories {
			if df.RelevantToConnection(net, transport) {
				detectors = append(detectors, df.NewDetector(net, transport, tcp))
			}
		}
	}

	return &tcpStream{
		net:            net,
		transport:      transport,
		reversed:       reversed,
		maxPacketCount: f.maxPacketCount,

		allowMissingInit: f.allowMissingInit,
		SYN:              false,

		detectors:    detectors,
		collector:    f.collectorFactory.NewCollector(net, transport, tcp),
		streamWriter: f.streamWriter,
	}
}

func (t *tcpStream) Accept(packet gopacket.Packet, tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection,
	nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	if !t.allowMissingInit && !t.SYN {
		if tcp.SYN {
			t.SYN = true
		} else {
			return false
		}
	}

	if t.reversed {
		dir = dir.Reverse()
	}

	// Determine the flow direction
	var dirString string
	if dir == reassembly.TCPDirClientToServer {
		dirString = fmt.Sprintf("%v %v(%s)", t.net, t.transport, dir)
		t.clientPacketCount++
	} else {
		dirString = fmt.Sprintf("%v %v(%s)", t.net.Reverse(), t.transport.Reverse(), dir)
		t.serverPacketCount++
	}
	logger.Debug.Printf("%s: Accept | S:%t, A:%t, P:%t, R:%t F:%t", dirString, tcp.SYN, tcp.ACK, tcp.PSH, tcp.RST, tcp.FIN)

	// stop processing the tcpStream when we reach the max packet count
	if t.clientPacketCount > t.maxPacketCount || t.serverPacketCount > t.maxPacketCount {
		return false
	}

	for _, det := range t.detectors {
		det.ProcessPacket(packet, tcp, ci, dir)
	}
	if t.collector != nil {
		t.collector.ProcessPacket(packet, tcp, ci, dir)
	}

	return true
}

func (t *tcpStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {

	dir, start, end, skip := sg.Info()
	length, saved := sg.Lengths()

	if t.reversed {
		dir = dir.Reverse()
	}

	// Determine the flow direction
	var dirString string
	if dir == reassembly.TCPDirClientToServer {
		dirString = fmt.Sprintf("%v %v(%s)", t.net, t.transport, dir)
	} else {
		dirString = fmt.Sprintf("%v %v(%s)", t.net.Reverse(), t.transport.Reverse(), dir)
	}

	sgStats := sg.Stats()
	logger.Debug.Printf("%s: ReassembledSG | %d bytes (start:%v,end:%v,skip:%d,saved:%d,nb:%d,%d,overlap:%d,%d)",
		dirString, length, start, end, skip, saved, sgStats.Packets,
		sgStats.Chunks, sgStats.OverlapBytes, sgStats.OverlapPackets)

	t.collector.ProcessReassembled(sg, ac, dir)

}

func (t *tcpStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	logger.Debug.Printf("%s %s: TCP Stream Reassembly Complete", t.net, t.transport)

	// do not remove the connection to see further along the connection
	return false
}

// Destroy:
// 	Only called once when the stream is about to be destroyed. There should be no more incoming
// 	packets at this point in the stream; we can now detect if disruption has occurred.
// NOTE: this is not part of the standard gopacket, but is part of the fork we're using
func (t *tcpStream) Destroy() {

	// Detect stream disruption
	var detectors []detector.Detector
	for _, det := range t.detectors {
		if !det.ProtocolDetected() {
			continue
		}
		disrupted := det.SignatureDetected()
		if disrupted {
			detectors = append(detectors, det)
		}
		StreamsCount.With(prometheus.Labels{"detector": det.Label(), "disrupted": strconv.FormatBool(disrupted)}).Inc()
	}

	// Log collected fields for disrupted streams
	disrupted := len(detectors) > 0
	if disrupted {
		t.streamWriter(detectors, t.collector)
		logger.Debug.Printf("%s %s: Disruption Detected", t.net, t.transport)
	}

	// Update global stream counter
	StreamsCount.With(prometheus.Labels{"detector": "global_streams", "disrupted": strconv.FormatBool(disrupted)}).Inc()
}

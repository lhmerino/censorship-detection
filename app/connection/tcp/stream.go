package tcp

/*
 * TCP stream
 */

import (
	"breakerspace.cs.umd.edu/censorship/measurement/detection/censor"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/shared"
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger"
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger/data"
	"fmt"
	"github.com/Kkevsterrr/gopacket"
	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/reassembly"
)

// Accept :
// Each packet in the TCP stream passes through here to determine if it should be considered for reassembly
func (t *Stream) Accept(packet *gopacket.Packet, tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection,
	nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {

	// Determine the flow direction
	var dirString string
	if dir == reassembly.TCPDirClientToServer {
		dirString = fmt.Sprintf("%v %v(%s)", t.net, t.transport, dir)
	} else {
		dirString = fmt.Sprintf("%v %v(%s)", t.net.Reverse(), t.transport.Reverse(), dir)
	}

	logger.Logger.Debug("%s: Accept | S:%t, A:%t, P:%t, R:%t F:%t", dirString, tcp.SYN, tcp.ACK, tcp.PSH, tcp.RST,
		tcp.FIN)

	// Censorship Measurement: Process Packet Header
	for i := 0; i < len(t.measurements); i++ {
		(*t.measurements[i].Censor).ProcessPacketHeader(t.measurementStorage[i], packet, tcp, &ci, &dir)
	}

	// Stream Information Collectors: Process Packet Header
	for i := 0; i < len(t.collectors); i++ {
		collector, ok := t.collectors[i].(shared.ProcessPacketHeaderInterface)
		if ok {
			collector.ProcessPacketHeader(t.collectorStorage[i], packet, tcp, &ci, &dir)
		}
	}

	return true
}

func (t *Stream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {

	dir, start, end, skip := sg.Info()
	length, saved := sg.Lengths()

	// Determine the flow direction
	var dirString string
	if dir == reassembly.TCPDirClientToServer {
		dirString = fmt.Sprintf("%v %v(%s)", t.net, t.transport, dir)
	} else {
		dirString = fmt.Sprintf("%v %v(%s)", t.net.Reverse(), t.transport.Reverse(), dir)
	}

	// Stream Information Collectors: Process Packet Payload
	for i := 0; i < len(t.collectors); i++ {
		collector, ok := t.collectors[i].(shared.ProcessPacketPayloadInterface)
		if ok {
			collector.ProcessPacketPayload(t.collectorStorage[i], &sg, &ac)
		}
	}

	sgStats := sg.Stats()
	logger.Logger.Debug("%s: ReassembledSG | %d bytes "+
		"(start:%v,end:%v,skip:%d,saved:%d,nb:%d,%d,overlap:%d,%d)",
		dirString, length,
		start, end, skip, saved, sgStats.Packets, sgStats.Chunks, sgStats.OverlapBytes, sgStats.OverlapPackets)

	return
}

func (t *Stream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	logger.Logger.Debug("%s %s: TCP Stream Reassembly Complete", t.net, t.transport)

	// do not remove the connection to see further along the connection
	return false
}

// Destroy:
// 	Only called once when the stream is about to be destroyed. There should be no more incoming
// 	packets at this point in the stream; we can now detect if censorship has occurred.
func (t *Stream) Destroy() {
	// Detect if censorship occurred in this stream
	censorshipDetected := false
	for i := 0; i < len(t.measurements); i++ {
		censorCensorshipDetected := (*t.measurements[i].Censor).DetectCensorship(t.measurementStorage[i])
		if censorCensorshipDetected == censor.DETECTED {
			censorshipDetected = true
		}
	}

	collectedData := make([]*data.Array, len(t.collectors))

	// Gather information about the stream if censorship has been detected
	for i := 0; i < len(t.collectors) && censorshipDetected; i++ {
		collectedData[i] = t.collectors[i].GetData(t.collectorStorage[i])
	}

	logger.Logger.Connection(&t.net, &t.transport, collectedData)
}

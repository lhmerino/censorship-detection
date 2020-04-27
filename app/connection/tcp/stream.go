package tcp

/*
 * TCP stream
 */

import (
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

// Each packet in the TCP stream passes through here to determine if it should be considered for reassembly
func (t *Stream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection,
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

	// Censorship Measurement: Process Packet
	for i := 0; i < len(t.measurements); i++ {
		(*t.measurements[i].Censor).ProcessPacket(t.measurementStorage[i], tcp, ci, dir)
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

	// Save request data from the client up to MAX_CONTENT_LENGTH
	if dir == reassembly.TCPDirClientToServer {
		// Get data sent by the client
		data := sg.Fetch(length)
		if (length + t.contents.Len()) < MAX_CONTENT_LENGTH {
			t.contents.Write(data)
		} else {
			for i := 0; i < MAX_CONTENT_LENGTH-t.contents.Len(); i++ {
				t.contents.WriteByte(data[i])
			}
		}
	}

	sgStats := sg.Stats()
	logger.Logger.Debug("%s: ReassembledSG | %d bytes, %d content saved "+
		"(start:%v,end:%v,skip:%d,saved:%d,nb:%d,%d,overlap:%d,%d)",
		dirString, length, t.contents.Len(),
		start, end, skip, saved, sgStats.Packets, sgStats.Chunks, sgStats.OverlapBytes, sgStats.OverlapPackets)

	return
}

func (t *Stream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	logger.Logger.Debug("%s %s: TCP Stream Reassembly Complete", t.net, t.transport)

	// Detect if censorship occurred in this stream
	for i := 0; i < len(t.measurements); i++ {
		(*t.measurements[i].Censor).DetectCensorship(t.measurementStorage[i], &t.net, &t.transport, &t.contents)
	}

	// do not remove the connection to see further along the connection
	return false
}

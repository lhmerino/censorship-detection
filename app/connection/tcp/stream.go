package tcp

/*
 * TCP stream
 */

import (
	"breakerspace.cs.umd.edu/censorship/measurement/detection/protocol"
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"sync"
)

type Options struct {
	allowMissingInit *bool
}

func NewTCPOptions(allowMissingInit *bool) *Options {
	return &Options{allowMissingInit: allowMissingInit}
}

/* It's a connection (bidirectional) */
type Stream struct {
	// TCP State
	tcpstate       *reassembly.TCPSimpleFSM
	fsmerr         bool
	optchecker     reassembly.TCPOptionCheck
	net, transport gopacket.Flow

	// TCP Options
	options *Options

	// TCP
	isDNS    bool
	isHTTP   bool
	reversed bool
	client   protocol.HttpReader
	//server   httpReader
	Urls  []string
	ident string
	sync.Mutex
}

func (t *Stream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	// FSM
	// All packets including ones that may be out of state should be logged.
	if !t.tcpstate.CheckState(tcp, dir) {
		logger.Error("FSM", "%s: Packet rejected by FSM (state:%s)\n", t.ident, t.tcpstate.String())
		//stats.rejectFsm++
		if !t.fsmerr {
			t.fsmerr = true
			//stats.rejectConnFsm++
		}
		/*if !*ignorefsmerr {
			return false
		}*/
	}
	// Options
	err := t.optchecker.Accept(tcp, ci, dir, nextSeq, start)
	if err != nil {
		logger.Error("OptionChecker", "%s: Packet rejected by OptionChecker: %s\n", t.ident, err)
		//stats.rejectOpt++
		/*if !*nooptcheck {
			return false
		}*/
	}

	return true

	// Ignore checksum check
	accept := true
	/*if *checksum {
		c, err := tcp.ComputeChecksum()
		if err != nil {
			Error("ChecksumCompute", "%s: Got error computing checksum: %s\n", t.ident, err)
			accept = false
		} else if c != 0x0 {
			Error("Checksum", "%s: Invalid checksum: 0x%x\n", t.ident, c)
			accept = false
		}
	}
	if !accept {
		//stats.rejectOpt++
	}*/
	return accept
}

func (t *Stream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	dir, start, end, skip := sg.Info()
	length, saved := sg.Lengths()
	// update stats
	sgStats := sg.Stats()
	if skip > 0 {
		//stats.missedBytes += skip
	}
	//stats.sz += length - saved
	//stats.pkt += sgStats.Packets
	if sgStats.Chunks > 1 {
		//stats.reassembled++
	}
	//stats.outOfOrderPackets += sgStats.QueuedPackets
	//stats.outOfOrderBytes += sgStats.QueuedBytes
	//if length > stats.biggestChunkBytes {
	//stats.biggestChunkBytes = length
	//}
	//if sgStats.Packets > stats.biggestChunkPackets {
	//stats.biggestChunkPackets = sgStats.Packets
	//}
	if sgStats.OverlapBytes != 0 && sgStats.OverlapPackets == 0 {
		fmt.Printf("bytes:%d, pkts:%d\n", sgStats.OverlapBytes, sgStats.OverlapPackets)
		panic("Invalid overlap")
	}
	//stats.overlapBytes += sgStats.OverlapBytes
	//stats.overlapPackets += sgStats.OverlapPackets

	var ident string
	if dir == reassembly.TCPDirClientToServer {
		ident = fmt.Sprintf("%v %v(%s): ", t.net, t.transport, dir)
	} else {
		ident = fmt.Sprintf("%v %v(%s): ", t.net.Reverse(), t.transport.Reverse(), dir)
	}
	logger.Debug("%s: SG reassembled packet with %d bytes (start:%v,end:%v,skip:%d,saved:%d,nb:%d,%d,overlap:%d,%d)\n", ident, length, start, end, skip, saved, sgStats.Packets, sgStats.Chunks, sgStats.OverlapBytes, sgStats.OverlapPackets)
	if skip == -1 && *t.options.allowMissingInit {
		// this is allowed
	} else if skip != 0 {
		// Missing bytes in stream: do not even try to parse it
		return
	}
	data := sg.Fetch(length)
	if t.isDNS {
		dns := &layers.DNS{}
		var decoded []gopacket.LayerType
		if len(data) < 2 {
			if len(data) > 0 {
				sg.KeepFrom(0)
			}
			return
		}
		dnsSize := binary.BigEndian.Uint16(data[:2])
		missing := int(dnsSize) - len(data[2:])
		logger.Debug("dnsSize: %d, missing: %d\n", dnsSize, missing)
		if missing > 0 {
			logger.Info("Missing some bytes: %d\n", missing)
			sg.KeepFrom(0)
			return
		}
		p := gopacket.NewDecodingLayerParser(layers.LayerTypeDNS, dns)
		err := p.DecodeLayers(data[2:], &decoded)
		if err != nil {
			logger.Error("DNS-parser", "Failed to decode DNS: %v\n", err)
		} else {
			logger.Debug("DNS: %s\n", gopacket.LayerDump(dns))
		}
		if len(data) > 2+int(dnsSize) {
			sg.KeepFrom(2 + int(dnsSize))
		}
	} else if t.isHTTP {
		if length > 0 {
			//if *hexdump {
			logger.Debug("Feeding http with:\n%s", hex.Dump(data))
			//}
			if dir == reassembly.TCPDirClientToServer && !t.reversed {
				t.client.Bytes <- data
			} else {
				//t.server.bytes <- data
			}
		}
	}
}

func (t *Stream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	logger.Debug("%s: Connection closed\n", t.ident)
	if t.isHTTP {
		close(t.client.Bytes)
		//close(t.server.bytes)
	}
	// do not remove the connection to allow last ACK
	return false
}

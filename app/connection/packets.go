package connection

import (
	"breakerspace.cs.umd.edu/censorship/measurement/connection/tcp"
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger"
	"encoding/hex"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"
	"os"
	"os/signal"
)

type Options struct {
	// Gathering of packets
	pcapFile *string
	iface    *string

	// Interface options
	snaplen *int

	// Packet Filter
	filter *string

	// Hex Dump Packet (up to snaplen)
	hexdump *bool

	//
}

func NewPacketOptions(pcapFile *string, iface *string, snaplen *int, filter *string, hexdump *bool) *Options {
	return &Options{pcapFile: pcapFile, iface: iface, snaplen: snaplen, filter: filter, hexdump: hexdump}
}

type Context struct {
	CaptureInfo gopacket.CaptureInfo
}

func (c *Context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}

func Run(options *Options, tcpOptions *tcp.Options) {
	var err error
	var handle *pcap.Handle

	if *options.pcapFile != "" {
		logger.Info("Read from pcap: %q\n", *options.pcapFile)
		handle, err = pcap.OpenOffline(*options.pcapFile)
	} else {
		logger.Info("Starting capture on interface %q\n", *options.iface)
		handle, err = pcap.OpenLive(*options.iface, int32(*options.snaplen), true, pcap.BlockForever)
	}

	if err != nil {
		logger.Error("Capture Handle", "Handle open failure: %s (%v,%+v)", err, err, err)
		return
	}

	defer handle.Close()

	// Filter packets given filter argument
	if err := handle.SetBPFFilter(*options.filter); err != nil {
		logger.Error("%s", err.Error())
	}

	// Set up assembly
	streamFactory := tcp.NewStreamFactory(tcpOptions)
	streamPool := reassembly.NewStreamPool(streamFactory)
	assembler := reassembly.NewAssembler(streamPool)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)

	count := 0

	for packet := range packetSource.Packets() {
		count++

		data := packet.Data()
		if *options.hexdump {
			logger.Debug("Packet #%d content (%d/0x%x)\n%s\n", count, len(data), len(data), hex.Dump(data))
		}

		// Ignore IPv4 de-fragmentation for the time being TODO
		tcpLayer := packet.Layer(layers.LayerTypeTCP)

		if tcpLayer != nil {
			// TCP Layer Detected
			tcpLayer := tcpLayer.(*layers.TCP)

			c := Context{
				CaptureInfo: packet.Metadata().CaptureInfo,
			}
			assembler.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), tcpLayer, &c)
		}
	}

	streamFactory.WaitGoRoutines()
	logger.Debug("%s\n", assembler.Dump())
}

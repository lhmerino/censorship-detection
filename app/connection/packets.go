package connection

import (
	"breakerspace.cs.umd.edu/censorship/measurement/connection/tcp"
	"breakerspace.cs.umd.edu/censorship/measurement/detection"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/censor"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/censor/fingerprint"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/protocol"
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"
	"os"
	"os/signal"
	"runtime"
	"time"
	"unsafe"
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

	// Flush/Close streams every X packets
	flush *uint64
}

func FlowProcessingOptions(pcapFile *string, iface *string, snaplen *int, filter *string, hexdump *bool,
	flush *uint64) *Options {
	return &Options{pcapFile: pcapFile, iface: iface, snaplen: snaplen, filter: filter, hexdump: hexdump, flush: flush}
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
		logger.Logger.Info("Read from pcap: %q", *options.pcapFile)
		handle, err = pcap.OpenOffline(*options.pcapFile)
	} else {
		logger.Logger.Info("Starting capture on interface %q", *options.iface)
		handle, err = pcap.OpenLive(*options.iface, int32(*options.snaplen), true, pcap.BlockForever)
	}

	if err != nil {
		logger.Logger.Error("Handle open failure: %s (%v,%+v)", err, err, err)
		return
	}

	defer handle.Close()

	// Filter packets given filter argument
	if err := handle.SetBPFFilter(*options.filter); err != nil {
		logger.Logger.Error("%s", err.Error())
	}

	// Set up assembler
	streamFactory := tcp.NewStreamFactory(tcpOptions)
	streamPool := reassembly.NewStreamPool(streamFactory)
	assembler := reassembly.NewAssembler(streamPool)

	// Interrupt setup
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)

	// Packet source setup
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	var count uint64 = 0
	done := 0

	for {
		select {
		case <-signalChan:
			logger.Logger.Info("SIGINT: abort")
			done = 1
			break
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				logger.Logger.Debug("End of PCAP")
				done = 1
				break
			}

			// Add count
			count += 1

			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer == nil {
				// If TCP layer does not exist
				logger.Logger.Debug("Unusable packet")
				continue
			}

			c := Context{
				CaptureInfo: packet.Metadata().CaptureInfo,
			}
			assembler.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), tcpLayer.(*layers.TCP), &c)

			// Time to flush or close connections
			if count%*options.flush == 0 {
				// Time reference to use when flushing or closing connections
				ref := packet.Metadata().CaptureInfo.Timestamp
				flushed, closed := assembler.FlushCloseOlderThan(ref.Add(time.Minute * -2))
				logger.Logger.Debug("Forced flush: %d flushed, %d closed", flushed, closed)
				//PrintMemUsage()
			}
		}
		if done == 1 {
			break
		}
	}

	closed := assembler.FlushAll()
	logger.Logger.Info("Final flush: %d closed", closed)
	logger.Logger.Debug("%s", assembler.Dump())
}

func PrintMemUsage() {

	fmt.Println("sizeof(stream)", unsafe.Sizeof(tcp.Stream{}))
	fmt.Println("sizeof(RSTACKs)", unsafe.Sizeof(fingerprint.RSTACKs{}))
	fmt.Println("sizeof(Measurement)", unsafe.Sizeof(detection.Measurement{}))
	fmt.Println("sizeof(China)", unsafe.Sizeof(censor.China{}))
	fmt.Println("sizeof(HTTP)", unsafe.Sizeof(protocol.HTTP{}))

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// For info on each, see: https://golang.org/pkg/runtime/#MemStats
	fmt.Printf("Alloc = %v MiB", bToMb(m.Alloc))
	fmt.Printf("\tHeapAlloc = %v MiB", bToMb(m.HeapAlloc))
	fmt.Printf("\tHeapObjects = %v MiB", bToMb(m.HeapObjects))
	fmt.Printf("\tTotalAlloc = %v MiB", bToMb(m.TotalAlloc))
	fmt.Printf("\tSys = %v MiB", bToMb(m.Sys))
	fmt.Printf("\tNumGC = %v", m.NumGC)
	fmt.Printf("\tMallocs = %v", m.Mallocs)
	fmt.Printf("\tFrees = %v\n", m.Frees)
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

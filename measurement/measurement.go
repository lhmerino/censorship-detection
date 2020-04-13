package main

import (
	"breakerspace.cs.umd.edu/censorship/measurement/censor"
	"breakerspace.cs.umd.edu/censorship/measurement/connection"
	"breakerspace.cs.umd.edu/censorship/measurement/protocol"
	"breakerspace.cs.umd.edu/censorship/measurement/utils"
	"flag"
)

//Measurement contains a specific Protocol and a specific Censor
type Interface interface {
	protocol.Interface
	censor.Interface
	processPacket()
}

type Measurement struct {
	Interface
	censor   *censor.Censor
	protocol *protocol.Protocol
}

// Array of measurements
var measurements []Measurement

// Parameters

// Logging Parameters
var verbose = flag.Bool("verbose", true, "Be verbose")
var debug = flag.Bool("debug", false, "Display debug information")
var quiet = flag.Bool("quiet", false, "Be quiet regarding errors")

// Packet Parameters
var pcapFile = flag.String("p", "", "PCAP file")
var iface = flag.String("i", "en0", "Interface to get packets from")
var snaplen = flag.Int("s", 1600, "SnapLen for pcap packet capture")
var filter = flag.String("f", "tcp and port 9999", "BPF filter for pcap")
var hexdump = flag.Bool("dump", false, "Dump HTTP request/response as hex")

func main() {
	flag.Parse()

	logger.SetupLogging(verbose, debug, quiet)
	logger.Debug("Logger started up...\n")

	measurements = make([]Measurement, 1)

	measurements[0].protocol = protocol.NewProtocol(protocol.HTTP)

	packetOptions := connection.NewPacketOptions(pcapFile, iface, snaplen, filter, hexdump)

	connection.Run(packetOptions)
}

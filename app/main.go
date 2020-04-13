package main

import (
	"breakerspace.cs.umd.edu/censorship/measurement/connection"
	"breakerspace.cs.umd.edu/censorship/measurement/connection/tcp"
	"breakerspace.cs.umd.edu/censorship/measurement/detection"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/censor"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/protocol"
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger"
	"flag"
)

// Array of measurements TODO
//var measurements []Measurement

// Parameters

// Logging Parameters
var verbose = flag.Bool("verbose", false, "Be verbose")
var debug = flag.Bool("debug", true, "Display debug information")
var quiet = flag.Bool("quiet", false, "Be quiet regarding errors")

// Packet Parameters
var pcapFile = flag.String("p", "", "PCAP file")
var iface = flag.String("i", "en0", "Interface to get packets from")
var snaplen = flag.Int("s", 1600, "SnapLen for pcap packet capture")
var filter = flag.String("f", "tcp and port 59168", "BPF filter for pcap")
var hexdump = flag.Bool("dump", false, "Dump HTTP request/response as hex")

// TCP options
var allowMissingInit = flag.Bool("allowmissinginit", false,
	"Support streams without SYN/SYN+ACK/ACK sequence")

func main() {
	flag.Parse()

	logger.SetupLogging(debug, verbose, quiet)
	logger.Debug("Logger started up...\n")

	//measurements = make([]Measurement, 1)

	protocolVar := protocol.NewProtocol(protocol.HTTP)
	censorVar := censor.NewCensor()

	measurementVar := detection.NewMeasurement(censorVar, protocolVar)

	packetOptions := connection.NewPacketOptions(pcapFile, iface, snaplen, filter, hexdump)
	tcpOptions := tcp.NewTCPOptions(allowMissingInit)

	connection.Run(measurementVar, packetOptions, tcpOptions)
}

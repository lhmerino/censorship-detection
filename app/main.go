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
var filter = flag.String("f", "", "BPF filter for pcap") // and port 59168
var hexdump = flag.Bool("dump", false, "Dump HTTP request/response as hex")

// TCP options
var allowMissingInit = flag.Bool("allowmissinginit", false,
	"Support streams without SYN/SYN+ACK/ACK sequence")

// HTTP Options
var httpPort = flag.Int("http_port", 80, "HTTP Server port")

func main() {
	flag.Parse()

	logger.SetupLogging(debug, verbose, quiet)
	logger.Debug("Logger started up...\n")

	createMeasurements()

	BPFFilter := *filter
	if BPFFilter == "" {
		BPFFilter = detection.GetBPFFilters(detection.Measurements)
	}

	logger.Info("BPF Filter: %s\n", BPFFilter)

	packetOptions := connection.NewPacketOptions(pcapFile, iface, snaplen, &BPFFilter, hexdump)
	tcpOptions := tcp.NewTCPOptions(allowMissingInit)

	connection.Run(packetOptions, tcpOptions)
}

func createMeasurements() {
	detection.Measurements = make([]*detection.Measurement, 2)

	protocolVar9999 := protocol.NewHTTP(9999)
	censorVar := censor.NewChina()
	detection.Measurements[0] = detection.NewMeasurement(censorVar, protocolVar9999)

	protocolVar8888 := protocol.NewHTTP(8888)
	detection.Measurements[1] = detection.NewMeasurement(censorVar, protocolVar8888)
}

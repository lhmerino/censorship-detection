package main

import (
	"breakerspace.cs.umd.edu/censorship/measurement/connection"
	"breakerspace.cs.umd.edu/censorship/measurement/connection/tcp"
	"breakerspace.cs.umd.edu/censorship/measurement/detection"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/censor"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/protocol"
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger"
	"flag"
	"fmt"
	"os"
	"syscall"
)

// Parameters

// Logging Parameters
var verbose = flag.Bool("verbose", true, "Be verbose")
var debug = flag.Bool("debug", false, "Display debug information")
var quiet = flag.Bool("quiet", false, "Be quiet regarding errors")

// Packet Parameters
var pcapFile = flag.String("p", "", "PCAP file")
var iface = flag.String("i", "en0", "Interface to get packets from")
var snaplen = flag.Int("s", 1600, "SnapLen for pcap packet capture")
var filter = flag.String("f", "", "BPF filter for pcap") // and port 59168
var hexdump = flag.Bool("dump", false, "Dump HTTP request/response as hex")
var flushStream = flag.Uint64("flush", 5, "Flush/Close streams every X packets")

// TCP options
var allowMissingInit = flag.Bool("allowmissinginit", false,
	"Support streams without SYN/SYN+ACK/ACK sequence")

// HTTP Options
var httpPort = flag.Int("http_port", 80, "HTTP Server port")

func main() {
	// Parse arguments
	flag.Parse()

	// Setup logging
	setupLogging()

	// Setup Measurements
	createMeasurements()

	// Construct BPF Filter (if not specified in arguments) to only
	// select flows that are relevant to the measurements created
	BPFFilter := *filter
	if BPFFilter == "" {
		BPFFilter = detection.GetBPFFilters(detection.Measurements)
	}

	logger.Logger.Info("BPF Filter: %s", BPFFilter)

	// Specify flow specific options (pcap vs. interface, snapshot length, filter, hexdump)
	packetOptions := connection.FlowProcessingOptions(pcapFile, iface, snaplen, &BPFFilter, hexdump, flushStream)
	// Specify TCP specific options
	tcpOptions := tcp.NewTCPOptions(allowMissingInit)

	// Configured main options, now run the application!
	connection.Run(packetOptions, tcpOptions)
}

func setupLogging() {
	fd, err := syscall.Open("/tmp/file.txt", syscall.O_WRONLY, 644)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Descriptor: %d, %s\n", fd, err)
	}

	logger.Logger = logger.NewPrint(fd, debug, verbose, quiet)
	logger.Logger.Debug("Logger started up...")
}

func createMeasurements() {
	detection.Measurements = make([]*detection.Measurement, 1)

	protocolVar9999 := protocol.NewHTTP()
	censorVar := censor.NewChina()
	detection.Measurements[0] = detection.NewMeasurement(censorVar, protocolVar9999)

	//protocolVar8888 := protocol.NewHTTPCustom(8888)
	//detection.Measurements[1] = detection.NewMeasurement(censorVar, protocolVar8888)
}

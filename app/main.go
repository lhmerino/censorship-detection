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
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"runtime/pprof"
	"syscall"
)

// Parameters

// Logging Parameters
var verbose = flag.Bool("verbose", false, "Display info level information")
var debug = flag.Bool("debug", false, "Display debug level information")
var quiet = flag.Bool("quiet", false, "Be quiet regarding errors")
var logFile = flag.String("log_file", "", "Log to File")
var logFD = flag.Int("log_fd", -1, "Log to file descriptor")

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

// Usage Profiles
var cpuProfile = flag.String("cpuprofile", "", "write cpu profile to `file` (priority over fd)")
var cpuProfileFd = flag.Int("cpuprofilefd", -1, "write cpu profile to `file descriptor`")
var memProfile = flag.String("memprofile", "", "write memory profile to `file` (priority over fd)")
var memProfileFd = flag.Int("memprofilefd", -1, "write memory profile to `file descriptor`")

var httpProfile = flag.Bool("http_profile", false, "HTTP Usage Profile")

func main() {
	// Parse arguments
	flag.Parse()

	// Setup logging
	setupLogging()

	cpuFile := setupProfile(cpuProfile, cpuProfileFd)
	memFile := setupProfile(memProfile, memProfileFd)

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

	// Turn on CPU profiling
	if cpuFile != nil {
		runtime.SetCPUProfileRate(500)
		if err := pprof.StartCPUProfile(cpuFile); err != nil {
			logger.Logger.Error("Could not start CPU profile: ", err)
			os.Exit(-2)
		}
	}

	if *httpProfile {
		go func() {
			log.Println(http.ListenAndServe("localhost:6060", nil))
		}()
	}

	// Configured main options, now run the application!
	connection.Run(packetOptions, tcpOptions)

	// Write CPU profile
	if cpuFile != nil {
		pprof.StopCPUProfile()
		cpuFile.Close()
	}

	// Write memory profile
	if memFile != nil {
		runtime.GC() // get up-to-date statistics
		if err := pprof.WriteHeapProfile(memFile); err != nil {
			log.Fatal("could not write memory profile: ", err)
		}
		memFile.Close()
	}
}

func setupLogging() {
	if *logFD == -1 && *logFile != "" {
		fd2, err := syscall.Open(*logFile, syscall.O_WRONLY, 644)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed to setup logging: %d, %s\n", fd2, err)
			os.Exit(-2)
		}
		*logFD = fd2
	}

	logger.Logger = logger.NewJSON(*logFD, debug, verbose, quiet)
	logger.Logger.Debug("Logger started up...")
}

func setupProfile(filepath *string, fd *int) *os.File {
	if *filepath != "" {
		// Profile to `file` (priority)
		file, err := os.Create(*filepath)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed to setup CPU profile (file): %s, %s\n", *filepath, err)
			os.Exit(-2)
		}
		return file
	} else if *fd != -1 {
		// Profile to file descriptor
		file := os.NewFile(uintptr(*fd), "Custom")
		return file
	}

	// No Profile
	return nil
}

func createMeasurements() {
	detection.Measurements = make([]*detection.Measurement, 1)

	protocolVar9999 := protocol.NewHTTPCustom(uint16(*httpPort))
	censorVar := censor.NewChina()
	detection.Measurements[0] = detection.NewMeasurement(censorVar, protocolVar9999)

	//protocolVar8888 := protocol.NewHTTPCustom(8888)
	//detection.Measurements[1] = detection.NewMeasurement(censorVar, protocolVar8888)
}

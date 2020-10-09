package setup

import (
	"breakerspace.cs.umd.edu/censorship/measurement/config"
	"breakerspace.cs.umd.edu/censorship/measurement/connection"
	"breakerspace.cs.umd.edu/censorship/measurement/connection/tcp"
	"breakerspace.cs.umd.edu/censorship/measurement/detection"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/collector"
	"breakerspace.cs.umd.edu/censorship/measurement/metrics"
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger"
	"fmt"
	"github.com/pkg/errors"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"runtime/pprof"
)

func StartConfiguration(cfg *config.Config) (*connection.Options, *tcp.Options, *os.File, *os.File) {
	// Setup logging
	logger.SetupLogging(cfg)

	var cpuFile *os.File = nil
	var memFile *os.File = nil
	if cfg.Profile.CPU.Enabled {
		cpuFile = setupProfile(&cfg.Profile.CPU.File, &cfg.Profile.CPU.Fd)
	}
	if cfg.Profile.Memory.Enabled {
		memFile = setupProfile(&cfg.Profile.Memory.File, &cfg.Profile.Memory.Fd)
	}

	// Setup Measurements
	detection.SetupMeasurements(&cfg.MeasurementConfigs)
	logger.Logger.Info("Measurements: %s", detection.GetBasicInfo(detection.Measurements))

	// Setup Collectors
	collector.SetupCollectors(cfg)
	logger.Logger.Info("Collectors: %s", collector.GetBasicInfo(collector.Collectors))

	// Construct BPF Filter (if not specified in arguments) to only
	// select flows that are relevant to the measurements created
	BPFFilter := cfg.Packet.Filter.BPF
	if BPFFilter == "" {
		BPFFilter = detection.GetBPFFilters(detection.Measurements)
	}

	logger.Logger.Info("BPF Filter: %s", BPFFilter)

	// Specify flow specific options (pcap vs. interface, snapshot length, filter, hexdump)
	packetOptions := connection.FlowProcessingOptions(
		&cfg.Packet.Input.PcapFile, &cfg.Packet.Input.Interface, &cfg.Packet.SnapLen, &BPFFilter,
		&cfg.Logging.PacketHexdump, &cfg.Packet.Flush)
	// Specify TCP specific options
	tcpOptions := tcp.NewTCPOptions(&cfg.Protocol.TCP.AllowMissingInit)

	// CPU Profiling
	if cpuFile != nil {
		runtime.SetCPUProfileRate(500)
		if err := pprof.StartCPUProfile(cpuFile); err != nil {
			logger.Logger.Error("Could not start CPU profile: ", err)
			os.Exit(-2)
		}
	}

	if cfg.Profile.HTTPServer.Enabled {
		go func() {
			log.Println(http.ListenAndServe("localhost:6060", nil))
		}()
	}

	// Start metrics
	if cfg.Metrics != nil {
		netw, addr := cfg.Metrics.Network(), cfg.Metrics.String()
		metricsListener, err := net.Listen(netw, addr)
		err = errors.Wrapf(err, "metrics, netw=%v, addr=%v", netw, addr)
		if err != nil {
			log.Fatal(err)
		}
		go metrics.Start(metricsListener)
	}

	return packetOptions, tcpOptions, cpuFile, memFile
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

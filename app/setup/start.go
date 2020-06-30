package setup

import (
	"breakerspace.cs.umd.edu/censorship/measurement/config"
	"breakerspace.cs.umd.edu/censorship/measurement/connection"
	"breakerspace.cs.umd.edu/censorship/measurement/connection/tcp"
	"breakerspace.cs.umd.edu/censorship/measurement/detection"
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger"
)

func StartConfiguration(cfg *config.Config) (*connection.Options, *tcp.Options){
	// Setup logging
	logger.SetupLogging(cfg)

	// TODO: Config File Profile Fix
	//var cpuFile *os.File
	//var memFile *os.File
	//if cfg.Profile.CPU.Enabled == true {
	//	cpuFile = setupProfile(cpuProfile, cpuProfileFd)
	//}
	//if cfg.Profile.Memory.Enabled == true {
	//	memFile = setupProfile(memProfile, memProfileFd)
	//}

	// Setup Measurements
	detection.SetupMeasurements(cfg)

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

	return packetOptions, tcpOptions

	// Turn on CPU profiling
	//if cpuFile != nil {
	//	runtime.SetCPUProfileRate(500)
	//	if err := pprof.StartCPUProfile(cpuFile); err != nil {
	//		logger.Logger.Error("Could not start CPU profile: ", err)
	//		os.Exit(-2)
	//	}
	//}
	//
	//if *httpProfile {
	//	go func() {
	//		log.Println(http.ListenAndServe("localhost:6060", nil))
	//	}()
	//}
}

//func setupProfile(filepath *string, fd *int) *os.File {
//	if *filepath != "" {
//		// Profile to `file` (priority)
//		file, err := os.Create(*filepath)
//		if err != nil {
//			_, _ = fmt.Fprintf(os.Stderr, "Failed to setup CPU profile (file): %s, %s\n", *filepath, err)
//			os.Exit(-2)
//		}
//		return file
//	} else if *fd != -1 {
//		// Profile to file descriptor
//		file := os.NewFile(uintptr(*fd), "Custom")
//		return file
//	}
//
//	// No Profile
//	return nil
//}

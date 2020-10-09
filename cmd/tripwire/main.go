package main

import (
	"flag"
	_ "net/http/pprof"

	"breakerspace.cs.umd.edu/censorship/measurement/config"
	"breakerspace.cs.umd.edu/censorship/measurement/connection"
	"breakerspace.cs.umd.edu/censorship/measurement/setup"
)

var (
	configFile           = flag.String("config_file", "config/config.yml", "Config file location")
	pcapFile             = flag.String("pcap", "", "PCAP file")
	logFile              = flag.String("log-file", "", "Path to log file")
	iface                = flag.String("iface", "", "Interface to get packets from")
	portFirstMeasurement = flag.Int("port", -1, "Override Port for first Measurement")
	BPFFilter            = flag.String("bpf", "", "Override BPFFilter")
)

func main() {
	// Parse arguments
	flag.Parse()

	// Config file
	cfg := config.ReadConfig(*configFile)

	// Override common arguments
	overrideArgs(&cfg)

	// Configure Application
	packetOptions, tcpOptions, cpuFile, memFile := setup.StartConfiguration(&cfg)

	// Run program
	connection.Run(packetOptions, tcpOptions)

	// Cleanup program
	setup.EndConfiguration(&cfg, cpuFile, memFile)
}

func overrideArgs(cfg *config.Config) {
	if *pcapFile != "" {
		cfg.Packet.Input.PcapFile = *pcapFile
	}
	if *iface != "" {
		cfg.Packet.Input.Interface = *iface
	}
	if *portFirstMeasurement != -1 {
		cfg.MeasurementConfigs[0].Port = uint16(*portFirstMeasurement)
	}
	if *BPFFilter != "" {
		cfg.Packet.Filter.BPF = *BPFFilter
	}
	if *logFile != "" {
		cfg.Logging.Output.File = *logFile
		cfg.Logging.Output.Fd = -1
	}
}

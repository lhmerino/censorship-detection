package main

import (
	"breakerspace.cs.umd.edu/censorship/measurement/config"
	"breakerspace.cs.umd.edu/censorship/measurement/connection"
	"breakerspace.cs.umd.edu/censorship/measurement/setup"
	"flag"
	_ "net/http/pprof"
)

// Config Parameters
var configFile = flag.String("config_file", "app/config/config.yml", "Config file location")

var pcapFile = flag.String("p", "", "PCAP file")
var iface = flag.String("i", "", "Interface to get packets from")

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
	setup.EndConfiguration(cpuFile, memFile)
}

func overrideArgs(cfg *config.Config) {
	if *pcapFile != "" {
		cfg.Packet.Input.PcapFile = *pcapFile
	} else if *iface != "" {
		cfg.Packet.Input.Interface = *iface
	}
}
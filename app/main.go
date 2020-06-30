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

// TODO: Override some convenient configuration options (pcap vs. interface)

// Usage Profiles - TODO
var cpuProfile = flag.String("cpuprofile", "", "write cpu profile to `file` (priority over fd)")
var cpuProfileFd = flag.Int("cpuprofilefd", -1, "write cpu profile to `file descriptor`")
var memProfile = flag.String("memprofile", "", "write memory profile to `file` (priority over fd)")
var memProfileFd = flag.Int("memprofilefd", -1, "write memory profile to `file descriptor`")

var httpProfile = flag.Bool("http_profile", false, "HTTP Usage Profile")

func main() {
	// Parse arguments
	flag.Parse()

	// Config file
	cfg := config.ReadConfig(*configFile)
	packetOptions, tcpOptions := setup.StartConfiguration(&cfg)

	connection.Run(packetOptions, tcpOptions)

	setup.EndConfiguration(&cfg)
}
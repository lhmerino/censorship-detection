package collector

import (
	"breakerspace.cs.umd.edu/censorship/measurement/config"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/collector/net"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/collector/tcp"
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger"
	"fmt"
	"os"
)

// SetupCollectors : Dynamic Collector Setup based on YAML config file
func SetupCollectors(cfg *config.Config) {
	Collectors = make([]Collector, len(cfg.Collectors.Net)+len(cfg.Collectors.TCP))

	collectorIndex := 0

	// Network Layer Collectors
	for i := range cfg.Collectors.Net {
		Collectors[collectorIndex] = ReadCollectorFromConfig(&cfg.Collectors.Net[i])
		collectorIndex += 1
	}

	// Transport Layer Collectors
	for i := range cfg.Collectors.TCP {
		Collectors[collectorIndex] = ReadCollectorFromConfig(&cfg.Collectors.TCP[i])
		collectorIndex += 1
	}
}

// ReadCensorFromMeasurementConfig :
//	Returns the censor implementation given the string value
//	specified in the measurement definition in the YAML file
func ReadCollectorFromConfig(collectorConfig *config.CollectorConfig) Collector {
	if collectorConfig.Type == "IP" {
		return net.NewIP()
	} else if collectorConfig.Type == "Ports" {
		return tcp.NewPorts()
	} else if collectorConfig.Type == "Flags" {
		return tcp.NewFlags()
	} else if collectorConfig.Type == "Payload" {
		return tcp.NewPayload(collectorConfig.Options.MaxLength, collectorConfig.Options.Direction)
	} else if collectorConfig.Type == "TTL" {
		return net.NewTTL()
	} else if collectorConfig.Type == "IPID" {
		return net.NewIPID()
	} else if collectorConfig.Type == "SeqNum" {
		return tcp.NewSeqNum()
	}

	logger.Logger.Error("[Config] Invalid Collector: %s\n", collectorConfig.Type)
	fmt.Printf("[Config] Invalid Collector: %s\n", collectorConfig.Type)
	os.Exit(1)
	return nil
}

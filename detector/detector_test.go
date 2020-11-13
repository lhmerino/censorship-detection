package detector

import (
	"github.com/Kkevsterrr/gopacket"
	"github.com/Kkevsterrr/gopacket/layers"
	"net"
	"testing"
	"tripwire/config"
)

func TestUnitDetectorFactory(t *testing.T) {
	var detectorConfigs []config.DetectorConfig
	detectorConfigs = append(detectorConfigs,
		config.DetectorConfig{
			Heuristic: "RSTACKs",
			Protocol:  "HTTP",
			Port:      80,
		})

	detectorConfigs = append(detectorConfigs,
		config.DetectorConfig{
			Heuristic: "ANY",
			Protocol:  "ANY",
			Port:      8080,
		})

	var detectorFactories []DetectorFactory
	for _, cfg := range detectorConfigs {
		df, err := NewDetectorFactory(cfg)
		if err != nil {
			t.Fatal(err)
		}
		detectorFactories = append(detectorFactories, df)
	}

	// Test RelevantToConnection
	srcIP := net.IP{1, 2, 3, 4}
	dstIP := net.IP{5, 6, 7, 8}
	netFlow, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(srcIP), layers.NewIPEndpoint(dstIP))
	transportFlow, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(4444), layers.NewTCPPortEndpoint(8080))

	var relevantDetectors []Detector
	for _, df := range detectorFactories {
		if df.RelevantToConnection(netFlow, transportFlow) {
			detector := df.NewDetector(netFlow, transportFlow, nil)
			relevantDetectors = append(relevantDetectors, detector)
		}
	}

	if len(relevantDetectors) != 1 {
		t.Fatalf("Expected %v but got %v", 1, len(relevantDetectors))
	}

	if !relevantDetectors[0].HeuristicDetected() {
		t.Fatalf("Expected %v but got %v", true, relevantDetectors[0].HeuristicDetected())
	}

	if relevantDetectors[0].Label() != "any_8080_any" {
		t.Fatalf("Expected %v but got %v", "any_8080_any", relevantDetectors[0].Label())
	}
}

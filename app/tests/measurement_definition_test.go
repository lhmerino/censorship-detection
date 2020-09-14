package tests

import (
	"breakerspace.cs.umd.edu/censorship/measurement/config"
	"breakerspace.cs.umd.edu/censorship/measurement/detection"
	"github.com/Kkevsterrr/gopacket"
	"github.com/Kkevsterrr/gopacket/layers"
	"net"
	"testing"
)

func TestBPFFilter(t *testing.T) {
	var measurementConfigs = make([]config.MeasurementConfig, 0)
	measurementConfigs = append(measurementConfigs,
		config.MeasurementConfig{
		Censor:   "China",
		Protocol: "HTTP",
		Port:     9999,
		Options:  config.MeasurementOptions{
			Direction: false,
		},
	})

	detection.Measurements = make([]*detection.Measurement, 1)
	detection.SetupMeasurements(&measurementConfigs)

	BPFFilter := detection.GetBPFFilters(detection.Measurements)
	expected := "(tcp and port 9999)"
	if BPFFilter != expected {
		t.Errorf("Expected %s but got %s", expected, BPFFilter)
	}

	// ------

	measurementConfigs = append(measurementConfigs,
		config.MeasurementConfig{
			Censor:   "China",
			Protocol: "HTTP",
			Port:     80,
			Options:  config.MeasurementOptions{
				Direction: false,
			},
		})

	measurementConfigs = append(measurementConfigs,
		config.MeasurementConfig{
			Censor:   "China",
			Protocol: "HTTP",
			Port:     8080,
			Options:  config.MeasurementOptions{
				Direction: false,
			},
		})
	detection.SetupMeasurements(&measurementConfigs)

	BPFFilter = detection.GetBPFFilters(detection.Measurements)
	expected = "(tcp and port 9999) or (tcp and port 80) or (tcp and port 8080)"
	if BPFFilter != expected {
		t.Errorf("Expected %s but got %s", expected, BPFFilter)
	}
}

func TestBasicInfo(t *testing.T) {
	var measurementConfigs = make([]config.MeasurementConfig, 0)

	measurementConfigs = append(measurementConfigs,
		config.MeasurementConfig{
			Censor:   "China",
			Protocol: "HTTP",
			Port:     80,
			Options:  config.MeasurementOptions{
				Direction: false,
			},
		})

	measurementConfigs = append(measurementConfigs,
		config.MeasurementConfig{
			Censor:   "China",
			Protocol: "HTTP",
			Port:     8080,
			Options:  config.MeasurementOptions{
				Direction: false,
			},
		})
	detection.SetupMeasurements(&measurementConfigs)

	basicInfo := detection.GetBasicInfo(detection.Measurements)
	expected := "China/HTTP on port 80 & China/HTTP on port 8080"
	if basicInfo != expected {
		t.Errorf("Expected %s but got %s", expected, basicInfo)
	}
}

func TestRelevantNewConnection(t *testing.T) {
	var measurementConfigs = make([]config.MeasurementConfig, 0)

	measurementConfigs = append(measurementConfigs,
		config.MeasurementConfig{
			Censor:   "China",
			Protocol: "HTTP",
			Port:     80,
			Options:  config.MeasurementOptions{
				Direction: false,
			},
		})

	measurementConfigs = append(measurementConfigs,
		config.MeasurementConfig{
			Censor:   "China",
			Protocol: "HTTP",
			Port:     8080,
			Options:  config.MeasurementOptions{
				Direction: false,
			},
		})
	measurementConfigs = append(measurementConfigs,
		config.MeasurementConfig{
			Censor:   "China",
			Protocol: "HTTP",
			Port:     8080,
			Options:  config.MeasurementOptions{
				Direction: false,
			},
		})
	detection.SetupMeasurements(&measurementConfigs)

	srcIP := net.IP{1, 2, 3, 4}
	dstIP := net.IP{5, 6, 7, 8}
	netFlow, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(srcIP), layers.NewIPEndpoint(dstIP))
	transportFlow, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(4444), layers.NewTCPPortEndpoint(8080))
	measurements := detection.RelevantNewConnection(detection.Measurements, netFlow, transportFlow)

	basicInfo := detection.GetBasicInfo(measurements)
	expected := "China/HTTP on port 8080 & China/HTTP on port 8080"
	if basicInfo != expected {
		t.Errorf("Expected %s but got %s", expected, basicInfo)
	}
}

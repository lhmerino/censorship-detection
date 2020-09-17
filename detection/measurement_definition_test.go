package detection

import (
	"breakerspace.cs.umd.edu/censorship/measurement/config"
	"github.com/Kkevsterrr/gopacket"
	"github.com/Kkevsterrr/gopacket/layers"
	"net"
	"testing"
)

func TestUnitBPFFilter(t *testing.T) {
	var measurementConfigs = make([]config.MeasurementConfig, 0)
	measurementConfigs = append(measurementConfigs,
		config.MeasurementConfig{
			Censor:   "China",
			Protocol: "HTTP",
			Port:     9999,
			Options: config.MeasurementOptions{
				Direction: false,
			},
		})

	Measurements = make([]*Measurement, 1)
	SetupMeasurements(&measurementConfigs)

	BPFFilter := GetBPFFilters(Measurements)
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
			Options: config.MeasurementOptions{
				Direction: false,
			},
		})

	measurementConfigs = append(measurementConfigs,
		config.MeasurementConfig{
			Censor:   "China",
			Protocol: "HTTP",
			Port:     8080,
			Options: config.MeasurementOptions{
				Direction: false,
			},
		})
	SetupMeasurements(&measurementConfigs)

	BPFFilter = GetBPFFilters(Measurements)
	expected = "(tcp and port 9999) or (tcp and port 80) or (tcp and port 8080)"
	if BPFFilter != expected {
		t.Errorf("Expected %s but got %s", expected, BPFFilter)
	}
}

func TestUnitBasicInfo(t *testing.T) {
	var measurementConfigs = make([]config.MeasurementConfig, 0)

	measurementConfigs = append(measurementConfigs,
		config.MeasurementConfig{
			Censor:   "China",
			Protocol: "HTTP",
			Port:     80,
			Options: config.MeasurementOptions{
				Direction: false,
			},
		})

	measurementConfigs = append(measurementConfigs,
		config.MeasurementConfig{
			Censor:   "China",
			Protocol: "HTTP",
			Port:     8080,
			Options: config.MeasurementOptions{
				Direction: false,
			},
		})
	SetupMeasurements(&measurementConfigs)

	basicInfo := GetBasicInfo(Measurements)
	expected := "China/HTTP on port 80 & China/HTTP on port 8080"
	if basicInfo != expected {
		t.Errorf("Expected %s but got %s", expected, basicInfo)
	}
}

func TestUnitRelevantNewConnection(t *testing.T) {
	var measurementConfigs = make([]config.MeasurementConfig, 0)

	measurementConfigs = append(measurementConfigs,
		config.MeasurementConfig{
			Censor:   "China",
			Protocol: "HTTP",
			Port:     80,
			Options: config.MeasurementOptions{
				Direction: false,
			},
		})

	measurementConfigs = append(measurementConfigs,
		config.MeasurementConfig{
			Censor:   "China",
			Protocol: "HTTP",
			Port:     8080,
			Options: config.MeasurementOptions{
				Direction: false,
			},
		})
	measurementConfigs = append(measurementConfigs,
		config.MeasurementConfig{
			Censor:   "China",
			Protocol: "HTTP",
			Port:     8080,
			Options: config.MeasurementOptions{
				Direction: false,
			},
		})
	SetupMeasurements(&measurementConfigs)

	srcIP := net.IP{1, 2, 3, 4}
	dstIP := net.IP{5, 6, 7, 8}
	netFlow, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(srcIP), layers.NewIPEndpoint(dstIP))
	transportFlow, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(4444), layers.NewTCPPortEndpoint(8080))
	measurements := RelevantNewConnection(Measurements, netFlow, transportFlow)

	basicInfo := GetBasicInfo(measurements)
	expected := "China/HTTP on port 8080 & China/HTTP on port 8080"
	if basicInfo != expected {
		t.Errorf("Expected %s but got %s", expected, basicInfo)
	}
}

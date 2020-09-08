package tests

import (
	"breakerspace.cs.umd.edu/censorship/measurement/detection"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/censor"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/protocol"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"testing"
)

func TestBPFFilter(t *testing.T) {
	detection.Measurements = make([]*detection.Measurement, 1)
	detection.Measurements[0] = detection.NewMeasurement(censor.NewChina(), protocol.NewHTTPCustom(9999))

	BPFFilter := detection.GetBPFFilters(detection.Measurements)
	expected := "(tcp and port 9999)"
	if BPFFilter != expected {
		t.Errorf("Expected %s but got %s", expected, BPFFilter)
	}

	detection.Measurements = make([]*detection.Measurement, 3)
	detection.Measurements[0] = detection.NewMeasurement(censor.NewChina(), protocol.NewHTTPCustom(9999))
	detection.Measurements[1] = detection.NewMeasurement(censor.NewChina(), protocol.NewHTTP())
	detection.Measurements[2] = detection.NewMeasurement(censor.NewChina(), protocol.NewHTTPCustom(8080))

	BPFFilter = detection.GetBPFFilters(detection.Measurements)
	expected = "(tcp and port 9999) or (tcp and port 80) or (tcp and port 8080)"
	if BPFFilter != expected {
		t.Errorf("Expected %s but got %s", expected, BPFFilter)
	}
}

func TestBasicInfo(t *testing.T) {
	detection.Measurements = make([]*detection.Measurement, 2)
	detection.Measurements[0] = detection.NewMeasurement(censor.NewChina(), protocol.NewHTTP())
	detection.Measurements[1] = detection.NewMeasurement(censor.NewChina(), protocol.NewHTTPCustom(8080))

	basicInfo := detection.GetBasicInfo(detection.Measurements)
	expected := "China/HTTP on port 80 & China/HTTP on port 8080"
	if basicInfo != expected {
		t.Errorf("Expected %s but got %s", expected, basicInfo)
	}
}

func TestRelevantNewConnection(t *testing.T) {
	detection.Measurements = make([]*detection.Measurement, 3)
	detection.Measurements[0] = detection.NewMeasurement(censor.NewChina(), protocol.NewHTTP())
	detection.Measurements[1] = detection.NewMeasurement(censor.NewChina(), protocol.NewHTTPCustom(8080))
	detection.Measurements[2] = detection.NewMeasurement(censor.NewChina(), protocol.NewHTTPCustom(8080))

	srcIP := net.IP{1, 2, 3, 4}
	dstIP := net.IP{5, 6, 7, 8}
	netFlow, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(srcIP), layers.NewIPEndpoint(dstIP))
	transportFlow, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(4444), layers.NewTCPPortEndpoint(8080))
	measurements := detection.RelevantNewConnection(detection.Measurements, netFlow, transportFlow)

	output := detection.GetBasicInfo(measurements)

	t.Log(output)
}

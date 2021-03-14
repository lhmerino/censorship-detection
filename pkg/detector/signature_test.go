package detector

import (
	"testing"
	"time"

	"github.com/Kkevsterrr/gopacket"
	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/reassembly"
)

func TestUnitRSTACKs(t *testing.T) {

	var tests = [][]struct {
		dir      reassembly.TCPFlowDirection
		tcp      layers.TCP
		detected bool
	}{
		{ // Test PSH, RST-ACK, RST-ACK sequence
			// TCP three-way handshake
			{detected: false, dir: reassembly.TCPDirClientToServer, tcp: layers.TCP{SYN: true}},
			{detected: false, dir: reassembly.TCPDirServerToClient, tcp: layers.TCP{SYN: true, ACK: true}},
			{detected: false, dir: reassembly.TCPDirClientToServer, tcp: layers.TCP{ACK: true}},
			// PSH simulating a censored query
			{detected: false, dir: reassembly.TCPDirClientToServer, tcp: layers.TCP{PSH: true}},
			// ACK the PSH
			{detected: false, dir: reassembly.TCPDirServerToClient, tcp: layers.TCP{ACK: true}},
			// First RST-ACK
			{detected: false, dir: reassembly.TCPDirClientToServer, tcp: layers.TCP{RST: true, ACK: true}},
			// Second RST-ACK
			{detected: true, dir: reassembly.TCPDirClientToServer, tcp: layers.TCP{RST: true, ACK: true}},
		},
		{ // Test PSH, RST, RST-ACK sequence
			// TCP three-way handshake
			{detected: false, dir: reassembly.TCPDirClientToServer, tcp: layers.TCP{SYN: true}},
			{detected: false, dir: reassembly.TCPDirServerToClient, tcp: layers.TCP{SYN: true, ACK: true}},
			{detected: false, dir: reassembly.TCPDirClientToServer, tcp: layers.TCP{ACK: true}},
			// PSH simulating a censored query
			{detected: false, dir: reassembly.TCPDirClientToServer, tcp: layers.TCP{PSH: true}},
			// ACK the PSH
			{detected: false, dir: reassembly.TCPDirServerToClient, tcp: layers.TCP{ACK: true}},
			// First RST
			{detected: false, dir: reassembly.TCPDirClientToServer, tcp: layers.TCP{RST: true}},
			// First RST-ACK
			{detected: true, dir: reassembly.TCPDirClientToServer, tcp: layers.TCP{RST: true, ACK: true}},
		},
	}

	for _, packets := range tests {
		signature := newRSTACKsSignature()

		for i, packet := range packets {
			signature.processPacket(&packet.tcp, packet.dir)
			if packet.detected != signature.detected() {
				t.Errorf("packet %d: got %v, want %v", i, signature.detected(), packet.detected)
			}
		}
	}
}

func TestUnitWin(t *testing.T) {
	var tests = [][]struct {
		dir      reassembly.TCPFlowDirection
		tcp      layers.TCP
		detected bool
	}{
		{ // Test RST, WIN sequence
			// TCP three-way handshake
			{detected: false, dir: reassembly.TCPDirClientToServer, tcp: layers.TCP{SYN: true}},
			{detected: false, dir: reassembly.TCPDirServerToClient, tcp: layers.TCP{SYN: true, ACK: true}},
			{detected: false, dir: reassembly.TCPDirClientToServer, tcp: layers.TCP{ACK: true}},
			// PSH simulating a censored query
			{detected: false, dir: reassembly.TCPDirClientToServer, tcp: layers.TCP{PSH: true}},
			// ACK the PSH
			{detected: false, dir: reassembly.TCPDirServerToClient, tcp: layers.TCP{ACK: true}},
			// RST-ACK but wrong window value to trigger signature
			{detected: false, dir: reassembly.TCPDirClientToServer, tcp: layers.TCP{RST: true, ACK: true, Window: 30}},
			// RST-ACK with correct window value to trigger signature
			{detected: true, dir: reassembly.TCPDirClientToServer, tcp: layers.TCP{RST: true, ACK: true, Window: 16}},
		},
	}

	for _, packets := range tests {
		signature := newWindowSignature()

		for i, packet := range packets {
			signature.processPacket(&packet.tcp, packet.dir)
			if packet.detected != signature.detected() {
				t.Errorf("packet %d: got %v, want %v", i, signature.detected(), packet.detected)
			}
		}
	}
}

func TestUnitTime(t *testing.T) {
	timeNow := time.Now()
	var tests = [][]struct {
		dir      reassembly.TCPFlowDirection
		ci       gopacket.CaptureInfo
		detected bool
	}{
		{
			// TCP three-way handshake
			{detected: false, dir: reassembly.TCPDirClientToServer,
				ci: gopacket.CaptureInfo{Timestamp: timeNow}},
			// Ensures only traffic from the client is being processed
			{detected: false, dir: reassembly.TCPDirServerToClient,
				ci: gopacket.CaptureInfo{Timestamp: timeNow.Add(100 * time.Millisecond)}},
			{detected: true, dir: reassembly.TCPDirClientToServer,
				ci: gopacket.CaptureInfo{Timestamp: timeNow.Add(4 * time.Millisecond)}},
			// Simulating a censored query
			{detected: true, dir: reassembly.TCPDirClientToServer,
				ci: gopacket.CaptureInfo{Timestamp: timeNow.Add(6 * time.Millisecond)}},
			// Acknowledge the client
			{detected: true, dir: reassembly.TCPDirServerToClient,
				ci: gopacket.CaptureInfo{Timestamp: timeNow.Add(10 * time.Millisecond)}},
			// Server acks the client again
			{detected: true, dir: reassembly.TCPDirServerToClient,
				ci: gopacket.CaptureInfo{Timestamp: timeNow.Add(12 * time.Millisecond)}},
			// Server once again acks the client - nothing from client
			{detected: true, dir: reassembly.TCPDirServerToClient,
				ci: gopacket.CaptureInfo{Timestamp: timeNow.Add(14 * time.Millisecond)}},
			// Received something from the client past threshold, no longer detected
			{detected: false, dir: reassembly.TCPDirClientToServer,
				ci: gopacket.CaptureInfo{Timestamp: timeNow.Add(21 * time.Millisecond)}},
		},
	}

	for _, packets := range tests {
		signature := newTimeSignature(10)

		for i, packet := range packets {
			signature.processPacket(packet.ci, packet.dir)
			if packet.detected != signature.detected() {
				t.Errorf("packet %d: got %v, want %v", i, signature.detected(), packet.detected)
			}
		}
	}
}

func TestUnitPacketCount(t *testing.T) {
	var tests = [][]struct {
		dir      reassembly.TCPFlowDirection
		detected bool
	}{
		{
			// Ensures only traffic from the client is being processed
			{detected: false, dir: reassembly.TCPDirServerToClient},
			// Client packet
			{detected: true, dir: reassembly.TCPDirClientToServer},
			// Server packet
			{detected: true, dir: reassembly.TCPDirServerToClient},
			// Client packet
			{detected: true, dir: reassembly.TCPDirClientToServer},
			// Server packet
			{detected: true, dir: reassembly.TCPDirServerToClient},
			// Another server packet
			{detected: true, dir: reassembly.TCPDirServerToClient},
			// Another server packet
			{detected: true, dir: reassembly.TCPDirServerToClient},
			// Client packet
			{detected: false, dir: reassembly.TCPDirClientToServer},
			// Another server packet
			{detected: false, dir: reassembly.TCPDirServerToClient},
		},
	}

	for _, packets := range tests {
		signature := newPacketCountSignature(2)

		for i, packet := range packets {
			signature.processPacket(packet.dir)
			if packet.detected != signature.detected() {
				t.Errorf("packet %d: got %v, want %v", i, signature.detected(), packet.detected)
			}
		}
	}
}

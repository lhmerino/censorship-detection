package detector

import (
	"testing"

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

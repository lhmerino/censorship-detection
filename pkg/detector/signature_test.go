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
		tcp      layers.TCP
		dir      reassembly.TCPFlowDirection
		ci       gopacket.CaptureInfo
		detected bool
	}{
		{
			// SYN (T)
			{detected: false,
				tcp: layers.TCP{SYN: true}, dir: reassembly.TCPDirClientToServer,
				ci: gopacket.CaptureInfo{Timestamp: timeNow},
			},
		},
		{
			// SYN (T) - SYN/ACK (T+1) - ACK (T+2)
			// PSH (T+3) - ACK (T+4) - ACK (T+5) - ACK(T+6) - PSH (T+11) - ACK (T+12)
			{detected: false,
				tcp: layers.TCP{SYN: true}, dir: reassembly.TCPDirClientToServer,
				ci: gopacket.CaptureInfo{Timestamp: timeNow},
			},
			{detected: false,
				tcp: layers.TCP{SYN: true, ACK: true}, dir: reassembly.TCPDirServerToClient,
				ci: gopacket.CaptureInfo{Timestamp: timeNow.Add(1 * time.Millisecond)},
			},
			{detected: false,
				tcp: layers.TCP{ACK: true}, dir: reassembly.TCPDirClientToServer,
				ci: gopacket.CaptureInfo{Timestamp: timeNow.Add(2 * time.Millisecond)},
			},
			{detected: true,
				tcp: layers.TCP{PSH: true, BaseLayer: layers.BaseLayer{Payload: []byte{1}}},
				dir: reassembly.TCPDirClientToServer,
				ci:  gopacket.CaptureInfo{Timestamp: timeNow.Add(3 * time.Millisecond)},
			},
			{detected: true,
				tcp: layers.TCP{ACK: true},
				dir: reassembly.TCPDirServerToClient,
				ci:  gopacket.CaptureInfo{Timestamp: timeNow.Add(4 * time.Millisecond)},
			},
			{detected: true,
				tcp: layers.TCP{ACK: true},
				dir: reassembly.TCPDirServerToClient,
				ci:  gopacket.CaptureInfo{Timestamp: timeNow.Add(5 * time.Millisecond)},
			},
			{detected: true,
				tcp: layers.TCP{ACK: true},
				dir: reassembly.TCPDirServerToClient,
				ci:  gopacket.CaptureInfo{Timestamp: timeNow.Add(6 * time.Millisecond)},
			},
			{detected: false,
				tcp: layers.TCP{PSH: true, BaseLayer: layers.BaseLayer{Payload: []byte{1}}},
				dir: reassembly.TCPDirClientToServer,
				ci:  gopacket.CaptureInfo{Timestamp: timeNow.Add(11 * time.Millisecond)},
			},
			{detected: false,
				tcp: layers.TCP{ACK: true},
				dir: reassembly.TCPDirServerToClient,
				ci:  gopacket.CaptureInfo{Timestamp: timeNow.Add(12 * time.Millisecond)},
			},
		},
		{
			// PSH (T) - PSH (T+10) - PSH (T+11) - PSH (T+200) - PSH(T+1000)
			{detected: true,
				tcp: layers.TCP{PSH: true, BaseLayer: layers.BaseLayer{Payload: []byte{1}}},
				dir: reassembly.TCPDirClientToServer,
				ci:  gopacket.CaptureInfo{Timestamp: timeNow},
			},
			{detected: true,
				tcp: layers.TCP{PSH: true, BaseLayer: layers.BaseLayer{Payload: []byte{1}}},
				dir: reassembly.TCPDirClientToServer,
				ci:  gopacket.CaptureInfo{Timestamp: timeNow.Add(10 * time.Millisecond)},
			},
			{detected: false,
				tcp: layers.TCP{PSH: true, BaseLayer: layers.BaseLayer{Payload: []byte{1}}},
				dir: reassembly.TCPDirClientToServer,
				ci:  gopacket.CaptureInfo{Timestamp: timeNow.Add(11 * time.Millisecond)},
			},
			{detected: false,
				tcp: layers.TCP{PSH: true, BaseLayer: layers.BaseLayer{Payload: []byte{1}}},
				dir: reassembly.TCPDirClientToServer,
				ci:  gopacket.CaptureInfo{Timestamp: timeNow.Add(200 * time.Millisecond)},
			},
			{detected: false,
				tcp: layers.TCP{PSH: true, BaseLayer: layers.BaseLayer{Payload: []byte{1}}},
				dir: reassembly.TCPDirClientToServer,
				ci:  gopacket.CaptureInfo{Timestamp: timeNow.Add(1000 * time.Millisecond)},
			},
		},
	}

	for testN, packets := range tests {
		signature := newTimeSignature(10)

		for i, packet := range packets {
			signature.processPacket(&packet.tcp, packet.ci, packet.dir)
			if packet.detected != signature.detected() {
				t.Errorf("Run: %d, packet %d: got %v, want %v", testN+1, i+1, signature.detected(), packet.detected)
			}
		}
	}
}

func TestUnitPacketCount(t *testing.T) {
	var tests = [][]struct {
		tcp      layers.TCP
		dir      reassembly.TCPFlowDirection
		detected bool
	}{
		{
			// SYN
			{detected: false,
				tcp: layers.TCP{SYN: true}, dir: reassembly.TCPDirClientToServer,
			},
		},
		{
			// SYN - SYN/ACK - ACK
			// PSH - ACK - ACK - ACK - PSH - ACK
			{detected: false,
				tcp: layers.TCP{SYN: true}, dir: reassembly.TCPDirClientToServer,
			},
			{detected: false,
				tcp: layers.TCP{SYN: true, ACK: true}, dir: reassembly.TCPDirServerToClient,
			},
			{detected: false,
				tcp: layers.TCP{ACK: true}, dir: reassembly.TCPDirClientToServer,
			},
			{detected: true,
				tcp: layers.TCP{PSH: true, BaseLayer: layers.BaseLayer{Payload: []byte{1}}},
				dir: reassembly.TCPDirClientToServer,
			},
			{detected: true,
				tcp: layers.TCP{ACK: true},
				dir: reassembly.TCPDirServerToClient,
			},
			{detected: true,
				tcp: layers.TCP{ACK: true},
				dir: reassembly.TCPDirServerToClient,
			},
			{detected: true,
				tcp: layers.TCP{ACK: true},
				dir: reassembly.TCPDirServerToClient,
			},
			{detected: false,
				tcp: layers.TCP{PSH: true, BaseLayer: layers.BaseLayer{Payload: []byte{1}}},
				dir: reassembly.TCPDirClientToServer,
			},
			{detected: false,
				tcp: layers.TCP{ACK: true},
				dir: reassembly.TCPDirServerToClient,
			},
		},
		{
			// PSH - PSH - PSH - PSH - PSH
			{detected: true,
				tcp: layers.TCP{PSH: true, BaseLayer: layers.BaseLayer{Payload: []byte{1}}},
				dir: reassembly.TCPDirClientToServer,
			},
			{detected: true,
				tcp: layers.TCP{PSH: true, BaseLayer: layers.BaseLayer{Payload: []byte{1}}},
				dir: reassembly.TCPDirClientToServer,
			},
			{detected: true,
				tcp: layers.TCP{PSH: true, BaseLayer: layers.BaseLayer{Payload: []byte{1}}},
				dir: reassembly.TCPDirClientToServer,
			},
			{detected: false,
				tcp: layers.TCP{PSH: true, BaseLayer: layers.BaseLayer{Payload: []byte{1}}},
				dir: reassembly.TCPDirClientToServer,
			},
			{detected: false,
				tcp: layers.TCP{PSH: true, BaseLayer: layers.BaseLayer{Payload: []byte{1}}},
				dir: reassembly.TCPDirClientToServer,
			},
		},
	}

	for _, packets := range tests {
		signature := newPacketCountSignature(3)

		for i, packet := range packets {
			signature.processPacket(&packet.tcp, packet.dir)
			if packet.detected != signature.detected() {
				t.Errorf("packet %d: got %v, want %v", i, signature.detected(), packet.detected)
			}
		}
	}
}

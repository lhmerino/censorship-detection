package tcpstream

import (
	"github.com/Kkevsterrr/gopacket"
	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/reassembly"
	"testing"
)

func TestUnitAllowMissingInit(t *testing.T) {
	var tests = [][]struct {
		allowMissingInit bool // First packet defines allowMissingInit for the entire TCP stream
		accept           bool // Whether tcpStream.Accept() should accept the packet
		tcp              layers.TCP
	}{
		{ // Three way handshake + PSH | Allow Missing Init: False
			{allowMissingInit: false,
				accept: true, tcp: layers.TCP{SYN: true}},
			{accept: true, tcp: layers.TCP{SYN: true, ACK: true}},
			{accept: true, tcp: layers.TCP{ACK: true}},
			{accept: true, tcp: layers.TCP{PSH: true}},
		},
		{ // Three way handshake + PSH | Allow Missing Init: True
			{allowMissingInit: true,
				accept: true, tcp: layers.TCP{SYN: true}},
			{accept: true, tcp: layers.TCP{SYN: true, ACK: true}},
			{accept: true, tcp: layers.TCP{ACK: true}},
			{accept: true, tcp: layers.TCP{PSH: true}},
		},
		{ // Immediate Content - Allow Missing Init: False
			{allowMissingInit: false, accept: false, tcp: layers.TCP{PSH: true}},
		},
		{ // Immediate Content - Allow Missing Init: True
			{allowMissingInit: true, accept: true, tcp: layers.TCP{PSH: true}},
		},
		{ // Immediate Content + SYN + New Content - Allow Missing Init: False
			{allowMissingInit: false,
				accept: false, tcp: layers.TCP{PSH: true}},
			{accept: false, tcp: layers.TCP{PSH: true}},
			{accept: true, tcp: layers.TCP{SYN: true}},
			{accept: true, tcp: layers.TCP{PSH: true}},
		},
		{ // Immediate Content + SYN + New Content - Allow Missing Init: True
			{allowMissingInit: true,
				accept: true, tcp: layers.TCP{PSH: true}},
			{accept: true, tcp: layers.TCP{PSH: true}},
			{accept: true, tcp: layers.TCP{SYN: true}},
			{accept: true, tcp: layers.TCP{PSH: true}},
		},
		{ // Accepts data after termination of stream | Allow Missing Init: False
			{allowMissingInit: false,
				accept: true, tcp: layers.TCP{SYN: true}},
			{accept: true, tcp: layers.TCP{PSH: true}},
			{accept: true, tcp: layers.TCP{RST: true}},
			{accept: true, tcp: layers.TCP{ACK: true, FIN: true}},
			{accept: true, tcp: layers.TCP{ACK: true}},
			{accept: true, tcp: layers.TCP{RST: true}},
			{accept: true, tcp: layers.TCP{RST: true}},
			{accept: true, tcp: layers.TCP{RST: true, ACK: true}},
		},
		{ // Accepts data after termination of stream | Allow Missing Init: True
			{allowMissingInit: true,
				accept: true, tcp: layers.TCP{SYN: true}},
			{accept: true, tcp: layers.TCP{PSH: true}},
			{accept: true, tcp: layers.TCP{RST: true}},
			{accept: true, tcp: layers.TCP{ACK: true, FIN: true}},
			{accept: true, tcp: layers.TCP{ACK: true}},
			{accept: true, tcp: layers.TCP{RST: true}},
			{accept: true, tcp: layers.TCP{RST: true}},
			{accept: true, tcp: layers.TCP{RST: true, ACK: true}},
		},
		{ // Brute Force (Random) - Allow Missing Init: False
			{allowMissingInit: false, accept: false, tcp: layers.TCP{PSH: true}},
			{accept: false, tcp: layers.TCP{ACK: true}},
			{accept: false, tcp: layers.TCP{RST: true}},
			{accept: false, tcp: layers.TCP{FIN: true}},
			{accept: false, tcp: layers.TCP{URG: true}},

			{accept: true, tcp: layers.TCP{SYN: true}},
			{accept: true, tcp: layers.TCP{PSH: true}},
			{accept: true, tcp: layers.TCP{ACK: true}},
			{accept: true, tcp: layers.TCP{RST: true}},
			{accept: true, tcp: layers.TCP{FIN: true}},
			{accept: true, tcp: layers.TCP{URG: true}},

			{accept: true, tcp: layers.TCP{SYN: true, PSH: true, ACK: true, RST: true, FIN: true, URG: true}},
		},
		{ // Brute Force (Random) - Allow Missing Init: True
			{allowMissingInit: true, accept: true, tcp: layers.TCP{PSH: true}},
			{accept: true, tcp: layers.TCP{ACK: true}},
			{accept: true, tcp: layers.TCP{RST: true}},
			{accept: true, tcp: layers.TCP{FIN: true}},
			{accept: true, tcp: layers.TCP{URG: true}},

			{accept: true, tcp: layers.TCP{SYN: true}},
			{accept: true, tcp: layers.TCP{PSH: true}},
			{accept: true, tcp: layers.TCP{ACK: true}},
			{accept: true, tcp: layers.TCP{RST: true}},
			{accept: true, tcp: layers.TCP{FIN: true}},
			{accept: true, tcp: layers.TCP{URG: true}},

			{accept: true, tcp: layers.TCP{SYN: true, PSH: true, ACK: true, RST: true, FIN: true, URG: true}},
		},
	}

	for test, packets := range tests {
		tcpStream := &tcpStream{
			allowMissingInit: packets[0].allowMissingInit,
			maxPacketCount:   25, // Must be larger than the biggest test size
		}

		for i, packet := range packets {
			// Pass in TCP layer - all other parameters do not have an effect on the outcome
			acceptResult := tcpStream.Accept(nil, &packet.tcp, gopacket.CaptureInfo{},
				reassembly.TCPDirClientToServer, 1, nil, nil)
			if packet.accept != acceptResult {
				t.Fatalf("test %d, packet %d: got %v, want %v", test, i, acceptResult, packet.accept)
			}
		}
	}
}

func TestUnitMaxPacketCount(t *testing.T) {
	var tests = [][]struct {
		accept bool // Whether tcpStream.Accept() should accept the packet
		dir    reassembly.TCPFlowDirection
		tcp    layers.TCP
	}{
		{ // Three way handshake + PSH + ACK + Connection Close | Client : 5 + Server: 3
			{accept: true, dir: reassembly.TCPDirClientToServer},
			{accept: true, dir: reassembly.TCPDirServerToClient},
			{accept: true, dir: reassembly.TCPDirClientToServer},
			{accept: true, dir: reassembly.TCPDirClientToServer},
			{accept: true, dir: reassembly.TCPDirServerToClient},
			{accept: true, dir: reassembly.TCPDirClientToServer},
			{accept: true, dir: reassembly.TCPDirServerToClient},
			{accept: true, dir: reassembly.TCPDirClientToServer},
		},
		{ // 10 Packets Client to Server | Client : 10
			{accept: true, dir: reassembly.TCPDirClientToServer},
			{accept: true, dir: reassembly.TCPDirClientToServer},
			{accept: true, dir: reassembly.TCPDirClientToServer},
			{accept: true, dir: reassembly.TCPDirClientToServer},
			{accept: true, dir: reassembly.TCPDirClientToServer},
			{accept: false, dir: reassembly.TCPDirClientToServer},
			{accept: false, dir: reassembly.TCPDirClientToServer},
			{accept: false, dir: reassembly.TCPDirClientToServer},
			{accept: false, dir: reassembly.TCPDirClientToServer},
			{accept: false, dir: reassembly.TCPDirClientToServer},
		},
		{ // 10 Packets Server to Client | Server: 10
			{accept: true, dir: reassembly.TCPDirServerToClient},
			{accept: true, dir: reassembly.TCPDirServerToClient},
			{accept: true, dir: reassembly.TCPDirServerToClient},
			{accept: true, dir: reassembly.TCPDirServerToClient},
			{accept: true, dir: reassembly.TCPDirServerToClient},
			{accept: false, dir: reassembly.TCPDirServerToClient},
			{accept: false, dir: reassembly.TCPDirServerToClient},
			{accept: false, dir: reassembly.TCPDirServerToClient},
			{accept: false, dir: reassembly.TCPDirServerToClient},
			{accept: false, dir: reassembly.TCPDirServerToClient},
		},
		{ // Client took our max packet count! | Client: 6 | Server: 3
			{accept: true, dir: reassembly.TCPDirClientToServer},
			{accept: true, dir: reassembly.TCPDirClientToServer},
			{accept: true, dir: reassembly.TCPDirClientToServer},
			{accept: true, dir: reassembly.TCPDirClientToServer},
			{accept: true, dir: reassembly.TCPDirClientToServer},
			{accept: false, dir: reassembly.TCPDirClientToServer},
			{accept: false, dir: reassembly.TCPDirClientToServer},
			{accept: false, dir: reassembly.TCPDirServerToClient},
			{accept: false, dir: reassembly.TCPDirServerToClient},
			{accept: false, dir: reassembly.TCPDirServerToClient},
		},
		{ // Server took our max packet count! | Client: 3 | Server: 7
			{accept: true, dir: reassembly.TCPDirServerToClient},
			{accept: true, dir: reassembly.TCPDirServerToClient},
			{accept: true, dir: reassembly.TCPDirServerToClient},
			{accept: true, dir: reassembly.TCPDirServerToClient},
			{accept: true, dir: reassembly.TCPDirServerToClient},
			{accept: false, dir: reassembly.TCPDirServerToClient},
			{accept: false, dir: reassembly.TCPDirServerToClient},
			{accept: false, dir: reassembly.TCPDirClientToServer},
			{accept: false, dir: reassembly.TCPDirClientToServer},
			{accept: false, dir: reassembly.TCPDirClientToServer},
		},
	}

	for test, packets := range tests {
		tcpStream := &tcpStream{
			allowMissingInit: true,
			maxPacketCount:   5,
		}

		for i, packet := range packets {
			// Pass in Direction - all other parameters do not have an effect on the outcome
			acceptResult := tcpStream.Accept(nil, &layers.TCP{}, gopacket.CaptureInfo{},
				packet.dir, 1, nil, nil)
			if packet.accept != acceptResult {
				t.Fatalf("test %d, packet %d: got %v, want %v", test, i, acceptResult, packet.accept)
			}
		}
	}
}

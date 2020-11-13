package detector

import (
	"testing"

	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/reassembly"
)

func TestUnitRSTACKs(t *testing.T) {
	rstAck := newRSTACKs()

	tcp := &layers.TCP{
		SYN: true,
	}
	dir := reassembly.TCPDirClientToServer
	rstAck.processPacket(tcp, dir)
	if rstAck.flags != 0 || rstAck.detected() != false {
		t.Errorf("[RSTACKs] Flag, expected 0, got %d or Censorship Triggered, expected false got %t",
			rstAck.flags, rstAck.detected())
	}

	tcp = &layers.TCP{
		SYN: true,
		ACK: true,
	}
	dir = reassembly.TCPDirServerToClient
	rstAck.processPacket(tcp, dir)
	if rstAck.flags != 0 || rstAck.detected() != false {
		t.Errorf("[RSTACKs] Flag, expected 0, got %d or Censorship Triggered, expected false got %t",
			rstAck.flags, rstAck.detected())
	}

	tcp = &layers.TCP{
		ACK: true,
	}
	dir = reassembly.TCPDirClientToServer
	rstAck.processPacket(tcp, dir)
	if rstAck.flags != 0 || rstAck.detected() != false {
		t.Errorf("[RSTACKs] Flag, expected 0, got %d or Censorship Triggered, expected false got %t",
			rstAck.flags, rstAck.detected())
	}

	// PSH simulating a censored query
	tcp = &layers.TCP{
		PSH: true,
	}
	dir = reassembly.TCPDirClientToServer
	rstAck.processPacket(tcp, dir)
	if rstAck.flags != 1 || rstAck.detected() != false {
		t.Errorf("[RSTACKs] Flag, expected 1, got %d or Censorship Triggered, expected false got %t",
			rstAck.flags, rstAck.detected())
	}

	// ACK the PSH
	tcp = &layers.TCP{
		ACK: true,
	}
	dir = reassembly.TCPDirServerToClient
	rstAck.processPacket(tcp, dir)
	if rstAck.flags != 1 || rstAck.detected() != false {
		t.Errorf("[RSTACKs] Flag, expected 1, got %d or Censorship Triggered, expected false got %t",
			rstAck.flags, rstAck.detected())
	}

	// First RST-ACK
	tcp = &layers.TCP{
		RST: true,
		ACK: true,
	}
	dir = reassembly.TCPDirClientToServer
	rstAck.processPacket(tcp, dir)
	if rstAck.flags != 3 || rstAck.detected() != false {
		t.Errorf("[RSTACKs] Flag, expected 3, got %d or Censorship Triggered, expected false got %t",
			rstAck.flags, rstAck.detected())
	}

	// Second RST-ACK
	tcp = &layers.TCP{
		RST: true,
		ACK: true,
	}
	dir = reassembly.TCPDirClientToServer
	rstAck.processPacket(tcp, dir)
	if rstAck.flags != 7 || rstAck.detected() != true {
		t.Errorf("[RSTACKs] Flag, expected 7, got %d or Censorship Triggered, expected true got %t",
			rstAck.flags, rstAck.detected())
	}

	// First RST
	tcp = &layers.TCP{
		RST: true,
	}
	dir = reassembly.TCPDirClientToServer
	rstAck.processPacket(tcp, dir)
	if rstAck.flags != 23 || rstAck.detected() != true {
		t.Errorf("[RSTACKs] Flag, expected 23, got %d or Censorship Triggered, expected true got %t",
			rstAck.flags, rstAck.detected())
	}

	// Third RST-ACK
	tcp = &layers.TCP{
		RST: true,
		ACK: true,
	}
	dir = reassembly.TCPDirClientToServer
	rstAck.processPacket(tcp, dir)
	if rstAck.flags != 31 || rstAck.detected() != true {
		t.Errorf("[RSTACKs] Flag, expected 31, got %d or Censorship Triggered, expected true got %t",
			rstAck.flags, rstAck.detected())
	}

	// Doesn't change anything (4th RST-ACK)
	tcp = &layers.TCP{
		RST: true,
		ACK: true,
	}
	dir = reassembly.TCPDirClientToServer
	rstAck.processPacket(tcp, dir)
	if rstAck.flags != 31 || rstAck.detected() != true {
		t.Errorf("[RSTACKs] Flag, expected 31, got %d or Censorship Triggered, expected true got %t",
			rstAck.flags, rstAck.detected())
	}

	// Second RST
	tcp = &layers.TCP{
		RST: true,
	}
	dir = reassembly.TCPDirClientToServer
	rstAck.processPacket(tcp, dir)
	if rstAck.flags != 63 || rstAck.detected() != true {
		t.Errorf("[RSTACKs] Flag, expected 63, got %d or Censorship Triggered, expected true got %t",
			rstAck.flags, rstAck.detected())
	}

	// Doesn't change anything (3rd RST)
	tcp = &layers.TCP{
		RST: true,
	}
	dir = reassembly.TCPDirClientToServer
	rstAck.processPacket(tcp, dir)
	if rstAck.flags != 63 || rstAck.detected() != true {
		t.Errorf("[RSTACKs] Flag, expected 63, got %d or Censorship Triggered, expected true got %t",
			rstAck.flags, rstAck.detected())
	}
}

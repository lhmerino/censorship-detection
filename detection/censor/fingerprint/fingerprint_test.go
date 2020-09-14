package fingerprint

import (
	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/reassembly"
	"testing"
)

func TestUnitRSTACKs(t *testing.T) {
	RstAck := NewRSTACKs(true)

	tcp := &layers.TCP{
		SYN: true,
	}
	dir := reassembly.TCPDirClientToServer
	RstAck.ProcessPacket(tcp, &dir)
	if RstAck.Flags != 0 || RstAck.CensorshipTriggered() != false {
		t.Errorf("[RSTACKs] Flag, expected 0, got %d or Censorship Triggered, expected false got %t",
			RstAck.Flags, RstAck.CensorshipTriggered())
	}

	tcp = &layers.TCP{
		SYN: true,
		ACK: true,
	}
	dir = reassembly.TCPDirServerToClient
	RstAck.ProcessPacket(tcp, &dir)
	if RstAck.Flags != 0 || RstAck.CensorshipTriggered() != false {
		t.Errorf("[RSTACKs] Flag, expected 0, got %d or Censorship Triggered, expected false got %t",
			RstAck.Flags, RstAck.CensorshipTriggered())
	}

	tcp = &layers.TCP{
		ACK: true,
	}
	dir = reassembly.TCPDirClientToServer
	RstAck.ProcessPacket(tcp, &dir)
	if RstAck.Flags != 0 || RstAck.CensorshipTriggered() != false {
		t.Errorf("[RSTACKs] Flag, expected 0, got %d or Censorship Triggered, expected false got %t",
			RstAck.Flags, RstAck.CensorshipTriggered())
	}

	// PSH simulating a censored query
	tcp = &layers.TCP{
		PSH: true,
	}
	dir = reassembly.TCPDirClientToServer
	RstAck.ProcessPacket(tcp, &dir)
	if RstAck.Flags != 1 || RstAck.CensorshipTriggered() != false {
		t.Errorf("[RSTACKs] Flag, expected 1, got %d or Censorship Triggered, expected false got %t",
			RstAck.Flags, RstAck.CensorshipTriggered())
	}

	// ACK the PSH
	tcp = &layers.TCP{
		ACK: true,
	}
	dir = reassembly.TCPDirServerToClient
	RstAck.ProcessPacket(tcp, &dir)
	if RstAck.Flags != 1 || RstAck.CensorshipTriggered() != false {
		t.Errorf("[RSTACKs] Flag, expected 1, got %d or Censorship Triggered, expected false got %t",
			RstAck.Flags, RstAck.CensorshipTriggered())
	}

	// First RST-ACK
	tcp = &layers.TCP{
		RST: true,
		ACK: true,
	}
	dir = reassembly.TCPDirClientToServer
	RstAck.ProcessPacket(tcp, &dir)
	if RstAck.Flags != 3 || RstAck.CensorshipTriggered() != false {
		t.Errorf("[RSTACKs] Flag, expected 3, got %d or Censorship Triggered, expected false got %t",
			RstAck.Flags, RstAck.CensorshipTriggered())
	}

	// Second RST-ACK
	tcp = &layers.TCP{
		RST: true,
		ACK: true,
	}
	dir = reassembly.TCPDirClientToServer
	RstAck.ProcessPacket(tcp, &dir)
	if RstAck.Flags != 7 || RstAck.CensorshipTriggered() != false {
		t.Errorf("[RSTACKs] Flag, expected 7, got %d or Censorship Triggered, expected false got %t",
			RstAck.Flags, RstAck.CensorshipTriggered())
	}

	// First RST
	tcp = &layers.TCP{
		RST: true,
	}
	dir = reassembly.TCPDirClientToServer
	RstAck.ProcessPacket(tcp, &dir)
	if RstAck.Flags != 23 || RstAck.CensorshipTriggered() != true {
		t.Errorf("[RSTACKs] Flag, expected 23, got %d or Censorship Triggered, expected true got %t",
			RstAck.Flags, RstAck.CensorshipTriggered())
	}

	// Third RST-ACK
	tcp = &layers.TCP{
		RST: true,
		ACK: true,
	}
	dir = reassembly.TCPDirClientToServer
	RstAck.ProcessPacket(tcp, &dir)
	if RstAck.Flags != 31 || RstAck.CensorshipTriggered() != true {
		t.Errorf("[RSTACKs] Flag, expected 31, got %d or Censorship Triggered, expected true got %t",
			RstAck.Flags, RstAck.CensorshipTriggered())
	}

	// Doesn't change anything (4th RST-ACK)
	tcp = &layers.TCP{
		RST: true,
		ACK: true,
	}
	dir = reassembly.TCPDirClientToServer
	RstAck.ProcessPacket(tcp, &dir)
	if RstAck.Flags != 31 || RstAck.CensorshipTriggered() != true {
		t.Errorf("[RSTACKs] Flag, expected 31, got %d or Censorship Triggered, expected true got %t",
			RstAck.Flags, RstAck.CensorshipTriggered())
	}

	// Second RST
	tcp = &layers.TCP{
		RST: true,
	}
	dir = reassembly.TCPDirClientToServer
	RstAck.ProcessPacket(tcp, &dir)
	if RstAck.Flags != 63 || RstAck.CensorshipTriggered() != true {
		t.Errorf("[RSTACKs] Flag, expected 63, got %d or Censorship Triggered, expected true got %t",
			RstAck.Flags, RstAck.CensorshipTriggered())
	}

	// Doesn't change anything (3rd RST)
	tcp = &layers.TCP{
		RST: true,
	}
	dir = reassembly.TCPDirClientToServer
	RstAck.ProcessPacket(tcp, &dir)
	if RstAck.Flags != 63 || RstAck.CensorshipTriggered() != true {
		t.Errorf("[RSTACKs] Flag, expected 63, got %d or Censorship Triggered, expected true got %t",
			RstAck.Flags, RstAck.CensorshipTriggered())
	}
}

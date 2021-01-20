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

func TestWin(t *testing.T) {
	heuristic := NewWindow()

	tcp := &layers.TCP{
		SYN: true,
	}
	dir := reassembly.TCPDirClientToServer
	heuristic.processPacket(tcp, dir)
	if heuristic.flags != 0 || heuristic.detected() != false {
		t.Errorf("[RSTACKs] Flag, expected 0, got %d or Censorship Triggered, expected false got %t",
			heuristic.flags, heuristic.detected())
	}

	tcp = &layers.TCP{
		SYN: true,
		ACK: true,
	}
	dir = reassembly.TCPDirServerToClient
	heuristic.processPacket(tcp, dir)
	if heuristic.flags != 0 || heuristic.detected() != false {
		t.Errorf("[RSTACKs] Flag, expected 0, got %d or Censorship Triggered, expected false got %t",
			heuristic.flags, heuristic.detected())
	}

	tcp = &layers.TCP{
		ACK: true,
	}
	dir = reassembly.TCPDirClientToServer
	heuristic.processPacket(tcp, dir)
	if heuristic.flags != 0 || heuristic.detected() != false {
		t.Errorf("[RSTACKs] Flag, expected 0, got %d or Censorship Triggered, expected false got %t",
			heuristic.flags, heuristic.detected())
	}

	// PSH simulating a censored query
	tcp = &layers.TCP{
		PSH: true,
	}
	dir = reassembly.TCPDirClientToServer
	heuristic.processPacket(tcp, dir)
	if heuristic.flags != 1 || heuristic.detected() != false {
		t.Errorf("[RSTACKs] Flag, expected 1, got %d or Censorship Triggered, expected false got %t",
			heuristic.flags, heuristic.detected())
	}

	// PSH simulating a censored query
	tcp = &layers.TCP{
		PSH: true,
		ACK: true,
	}
	dir = reassembly.TCPDirClientToServer
	heuristic.processPacket(tcp, dir)
	if heuristic.flags != 1 || heuristic.detected() != false {
		t.Errorf("[RSTACKs] Flag, expected 1, got %d or Censorship Triggered, expected false got %t",
			heuristic.flags, heuristic.detected())
	}

	// PSH simulating a censored query
	tcp = &layers.TCP{
		RST: true,
		Window: 32,
	}
	dir = reassembly.TCPDirClientToServer
	heuristic.processPacket(tcp, dir)
	if heuristic.flags != 1 || heuristic.detected() != false {
		t.Errorf("[RSTACKs] Flag, expected 1, got %d or Censorship Triggered, expected false got %t",
			heuristic.flags, heuristic.detected())
	}

	// PSH simulating a censored query
	tcp = &layers.TCP{
		RST: true,
		Window: 16,
	}
	dir = reassembly.TCPDirClientToServer
	heuristic.processPacket(tcp, dir)
	if heuristic.flags != 1 || heuristic.detected() != true {
		t.Errorf("[RSTACKs] Flag, expected 1, got %d or Censorship Triggered, expected false got %t",
			heuristic.flags, heuristic.detected())
	}
}

func TestUnitWin(t *testing.T) {
	heuristic := NewWindow()

	tcp := &layers.TCP{
		SYN: true,
	}
	dir := reassembly.TCPDirClientToServer
	heuristic.processPacket(tcp, dir)
	if heuristic.flags != 0 || heuristic.detected() != false {
		t.Errorf("[WIN] Flag, expected 0, got %d or Censorship Triggered, expected false got %t",
			heuristic.flags, heuristic.detected())
	}

	tcp = &layers.TCP{
		SYN: true,
		ACK: true,
	}
	dir = reassembly.TCPDirServerToClient
	heuristic.processPacket(tcp, dir)
	if heuristic.flags != 0 || heuristic.detected() != false {
		t.Errorf("[WIN] Flag, expected 0, got %d or Censorship Triggered, expected false got %t",
			heuristic.flags, heuristic.detected())
	}

	tcp = &layers.TCP{
		ACK: true,
	}
	dir = reassembly.TCPDirClientToServer
	heuristic.processPacket(tcp, dir)
	if heuristic.flags != 0 || heuristic.detected() != false {
		t.Errorf("[WIN] Flag, expected 0, got %d or Censorship Triggered, expected false got %t",
			heuristic.flags, heuristic.detected())
	}

	// PSH simulating a censored query
	tcp = &layers.TCP{
		PSH: true,
	}
	dir = reassembly.TCPDirClientToServer
	heuristic.processPacket(tcp, dir)
	if heuristic.flags != 1 || heuristic.detected() != false {
		t.Errorf("[WIN] Flag, expected 1, got %d or Censorship Triggered, expected false got %t",
			heuristic.flags, heuristic.detected())
	}

	// ACK the PSH
	tcp = &layers.TCP{
		ACK: true,
	}
	dir = reassembly.TCPDirServerToClient
	heuristic.processPacket(tcp, dir)
	if heuristic.flags != 1 || heuristic.detected() != false {
		t.Errorf("[WIN] Flag, expected 1, got %d or Censorship Triggered, expected false got %t",
			heuristic.flags, heuristic.detected())
	}

	// First RST-ACK but incorrect window size
	tcp = &layers.TCP{
		RST: true,
		ACK: true,
		Window: 30,
	}
	dir = reassembly.TCPDirClientToServer
	heuristic.processPacket(tcp, dir)
	if heuristic.flags != 1 || heuristic.detected() != false {
		t.Errorf("[WIN] Flag, expected 1, got %d or Censorship Triggered, expected false got %t",
			heuristic.flags, heuristic.detected())
	}

	// Second RST-ACK with correct window size
	tcp = &layers.TCP{
		RST: true,
		ACK: true,
		Window: 16,
	}
	dir = reassembly.TCPDirClientToServer
	heuristic.processPacket(tcp, dir)
	if heuristic.flags != 3 || heuristic.detected() != true {
		t.Errorf("[WIN] Flag, expected 3, got %d or Censorship Triggered, expected true got %t",
			heuristic.flags, heuristic.detected())
	}
}

func TestUnitRstAckRes(t *testing.T) {
	heuristic := newRstAckRes()

	tcp := &layers.TCP{
		SYN: true,
	}
	dir := reassembly.TCPDirClientToServer
	heuristic.processPacket(tcp, dir)
	if heuristic.flags != 0 || heuristic.detected() != false {
		t.Errorf("[RstAckRes] Flag, expected 0, got %d or Censorship Triggered, expected false got %t",
			heuristic.flags, heuristic.detected())
	}

	tcp = &layers.TCP{
		SYN: true,
		ACK: true,
	}
	dir = reassembly.TCPDirServerToClient
	heuristic.processPacket(tcp, dir)
	if heuristic.flags != 0 || heuristic.detected() != false {
		t.Errorf("[RstAckRes] Flag, expected 0, got %d or Censorship Triggered, expected false got %t",
			heuristic.flags, heuristic.detected())
	}

	tcp = &layers.TCP{
		ACK: true,
	}
	dir = reassembly.TCPDirClientToServer
	heuristic.processPacket(tcp, dir)
	if heuristic.flags != 0 || heuristic.detected() != false {
		t.Errorf("[RstAckRes] Flag, expected 0, got %d or Censorship Triggered, expected false got %t",
			heuristic.flags, heuristic.detected())
	}

	// First RST-ACK
	tcp = &layers.TCP{
		RST: true,
		ACK: true,
	}
	dir = reassembly.TCPDirClientToServer
	heuristic.processPacket(tcp, dir)
	if heuristic.flags != 2 || heuristic.detected() != false {
		t.Errorf("[RstAckRes] Flag, expected 2, got %d or Censorship Triggered, expected false got %t",
			heuristic.flags, heuristic.detected())
	}

	// Second RST-ACK
	tcp = &layers.TCP{
		RST: true,
		ACK: true,
	}
	dir = reassembly.TCPDirClientToServer
	heuristic.processPacket(tcp, dir)
	if heuristic.flags != 6 || heuristic.detected() != false {
		t.Errorf("[RstAckRes] Flag, expected 6, got %d or Censorship Triggered, expected false got %t",
			heuristic.flags, heuristic.detected())
	}

	// Third RST-ACK
	tcp = &layers.TCP{
		RST: true,
		ACK: true,
	}
	dir = reassembly.TCPDirClientToServer
	heuristic.processPacket(tcp, dir)
	if heuristic.flags != 14 || heuristic.detected() != true {
		t.Errorf("[RstAckRes] Flag, expected 14, got %d or Censorship Triggered, expected true got %t",
			heuristic.flags, heuristic.detected())
	}

	// PSH simulating a censored query
	tcp = &layers.TCP{
		PSH: true,
	}
	dir = reassembly.TCPDirClientToServer
	heuristic.processPacket(tcp, dir)
	if heuristic.flags != 15 || heuristic.detected() != false {
		t.Errorf("[RstAckRes] Flag, expected 1, got %d or Censorship Triggered, expected false got %t",
			heuristic.flags, heuristic.detected())
	}
}
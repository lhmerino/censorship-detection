package tcp

import (
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger/data"
	"fmt"
	"github.com/Kkevsterrr/gopacket"
	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/reassembly"
)

// Collects sequence numbers (Seq, Ack) as the packets are processed.


// SeqNum : Define config level struct
type SeqNum struct {

}

// SeqNum Stream : Define stream level struct
type SeqNumStream struct {
	seq []uint32
	ack []uint32
}

// ------- Seq Num Methods ---------

// NewSeqNum : Creates the config level struct
func NewSeqNum() *SeqNum {
	return &SeqNum{}
}

// GetName : Description of this interface
func (s *SeqNum) GetName() string {
	return "[TCP - SeqNum]"
}

// RelevantNewConnection : For now, only working with TCP packets so must be true
func (s *SeqNum) RelevantNewConnection(net, transport gopacket.Flow) bool {
	return true
}

// GetBasicInfo : No options available - return only its name
func (s *SeqNum) GetBasicInfo() string {
	return s.GetName()
}

// GetData : Returns array (each packet) of string values of Seq Num
func(s *SeqNum) GetData(someInterface interface{}) *data.Array {
	SeqNumStream := someInterface.(*SeqNumStream)

	sequences := make([]string, 0)

	for i, _ := range SeqNumStream.seq {
		sequences = append(sequences, fmt.Sprintf("S:%d-A:%d", SeqNumStream.seq[i], SeqNumStream.ack[i]))
	}

	return data.NewArray(s.GetName(), sequences)
}

// NewStream : Create stream level struct to store the seq num of each packet
func (p *SeqNum) NewStream(net, transport *gopacket.Flow, tcp *layers.TCP) interface{} {
	return NewSeqNumStream()
}

// ProcessPacketHeader : Appends flags for packet to FlagsStream
func (p *SeqNum) ProcessPacketHeader(someInterface interface{}, packet *gopacket.Packet, tcp *layers.TCP,
	ci *gopacket.CaptureInfo, dir *reassembly.TCPFlowDirection) {
	flagsStream := someInterface.(*SeqNumStream)

	flagsStream.Append(tcp)
}

// ------- Seq Num Stream Methods --

func NewSeqNumStream() *SeqNumStream {
	seq := make([]uint32, 0)
	ack := make([]uint32, 0)

	return &SeqNumStream{seq: seq, ack: ack}
}

func (s *SeqNumStream) Append(tcp *layers.TCP) {
	s.seq = append(s.seq, tcp.Seq)
	s.ack = append(s.ack, tcp.Ack)
}

// GetData : Returns an array of seq num for each packet in the format "seqNum-ackNum"
func (s *SeqNumStream) GetData() []string {
	seqNum := make([]string, 0)

	for i, _ := range s.ack {
		seqNum = append(seqNum, fmt.Sprintf("%d-%d", s.seq[i], s.ack[i]))
	}

	return seqNum
}
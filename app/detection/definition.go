package detection

import (
	"breakerspace.cs.umd.edu/censorship/measurement/detection/censor"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/protocol"
)

//Measurement contains a specific Protocol and a specific Censor
type Interface interface {
	processPacket()
}

type Measurement struct {
	//Interface
	Censor   censor.Censor
	Protocol protocol.Protocol
	Stats    stats

	// Protocol Options
	Port int
}

//var Measurements []Measurement

func NewMeasurement(censor censor.Censor, protocol protocol.Protocol) *Measurement {
	return &Measurement{Censor: censor, Protocol: protocol}
}

type stats struct {
	ipdefrag            int
	missedBytes         int
	pkt                 int
	sz                  int
	totalsz             int
	rejectFsm           int
	rejectOpt           int
	rejectConnFsm       int
	reassembled         int
	outOfOrderBytes     int
	outOfOrderPackets   int
	biggestChunkBytes   int
	biggestChunkPackets int
	overlapBytes        int
	overlapPackets      int
}

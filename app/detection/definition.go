package detection

import (
	"breakerspace.cs.umd.edu/censorship/measurement/detection/censor"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/protocol"
)

//Measurement contains a specific Protocol and a specific Censor
type Interface interface {
	protocol.Interface
	censor.Interface
	processPacket()
}

type Measurement struct {
	//Interface
	censor   *censor.Censor
	protocol *protocol.Protocol
	stats    stats
}

func NewMeasurement(censor *censor.Censor, protocol *protocol.Protocol) *Measurement {
	return &Measurement{censor: censor, protocol: protocol}
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

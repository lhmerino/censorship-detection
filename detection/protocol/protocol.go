package protocol

import (
	"breakerspace.cs.umd.edu/censorship/measurement/detection/shared"
)

type Protocol interface {
	shared.MainInterface

	// BPF filter for protocol
	GetBPFFilter() string

	GetPort() uint16
}

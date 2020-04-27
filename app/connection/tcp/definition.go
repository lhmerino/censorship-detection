package tcp

import (
	"breakerspace.cs.umd.edu/censorship/measurement/detection"
	"bytes"
	"github.com/google/gopacket"
	"sync"
)

var MAX_CONTENT_LENGTH = 1000

/* It's a connection (bidirectional) */
type Stream struct {
	// TCP State
	net, transport gopacket.Flow

	// Applicable Measurements
	measurements       []*detection.Measurement
	measurementStorage map[int]interface{}

	// Contains the first X bytes of the TCP payload (reassembled)
	contents bytes.Buffer

	sync.Mutex
}

type Options struct {
	// Create flows without actual TCP handshake
	allowMissingInit *bool
}

func NewTCPOptions(allowMissingInit *bool) *Options {
	return &Options{allowMissingInit: allowMissingInit}
}

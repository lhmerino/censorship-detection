package tcp

import (
	"breakerspace.cs.umd.edu/censorship/measurement/detection"
	"bytes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/reassembly"
	"sync"
)

var MAX_CONTENT_LENGTH = 1000

/* It's a connection (bidirectional) */
type Stream struct {
	// TCP State
	tcpstate       *reassembly.TCPSimpleFSM
	fsmerr         bool
	optchecker     reassembly.TCPOptionCheck
	net, transport gopacket.Flow
	ident          string

	// TCP Options
	options *Options

	// Applicable Measurements
	measurements []*detection.Measurement

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

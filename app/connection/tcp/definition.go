package tcp

import (
	"breakerspace.cs.umd.edu/censorship/measurement/detection"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/collector"
	"github.com/Kkevsterrr/gopacket"
	"sync"
)

var MAX_CONTENT_LENGTH = 1000

/* It's a connection (bidirectional) */
type Stream struct {
	// Parties in this connection
	// (net with transport = stream unique identifier)
	net, transport gopacket.Flow

	// Applicable Measurements
	measurements       	[]*detection.Measurement
	// Measurement related structs is stored as part of the stream struct
	// so that they get "destroyed" when the stream gets destroyed
	measurementStorage 	map[int]interface{}

	// Applicable Collectors
	collectors			[]collector.Collector
	// Collector related structs (same caveat as measurementStore)
	collectorStorage 	map[int]interface{}

	sync.Mutex
}

type Options struct {
	// Create flows without actual TCP handshake
	allowMissingInit *bool
}

func NewTCPOptions(allowMissingInit *bool) *Options {
	return &Options{allowMissingInit: allowMissingInit}
}

package logger

import (
	"bytes"
	"github.com/google/gopacket"
)

var Logger Logging

type Logging interface {
	// Debug - arbitrary string
	Debug(s string, a ...interface{})

	// Info - arbitrary string
	Info(s string, a ...interface{})

	// Error - arbitrary string
	Error(s string, a ...interface{})

	// Connection - specific arguments
	Connection(net *gopacket.Flow, transport *gopacket.Flow, content *bytes.Buffer)
}

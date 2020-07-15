package logger

import (
	"breakerspace.cs.umd.edu/censorship/measurement/config"
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"os"
)

type Print struct {
	outputLevel uint8
	file        *os.File
}

func NewPrint(cfg *config.Config) *Print {
	p := &Print{}

	p.file, p.outputLevel = commonSetup(cfg)

	return p
}

func (l *Print) Debug(s string, a ...interface{}) {
	if l.outputLevel >= 3 {
		_, _ = fmt.Fprintf(l.file, s, a...)
		_, _ = fmt.Fprintln(l.file)
	}
}

func (l *Print) Info(s string, a ...interface{}) {
	if l.outputLevel >= 2 {
		_, _ = fmt.Fprintf(l.file, s, a...)
		_, _ = fmt.Fprintln(l.file)
	}
}

func (l *Print) Error(s string, a ...interface{}) {
	if l.outputLevel >= 1 {
		_, _ = fmt.Fprintf(l.file, s, a...)
		_, _ = fmt.Fprintln(l.file)
	}
}

func (l *Print) Connection(net *gopacket.Flow, transport *gopacket.Flow, content *bytes.Buffer) {
	_, _ = fmt.Fprintf(l.file, "%s %s: Censorship Detected\n%s", net, transport, hex.Dump(content.Bytes()))
}

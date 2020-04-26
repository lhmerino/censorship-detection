package logger

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"os"
	"syscall"
)

type Print struct {
	Logging
	outputLevel uint8
	file        *os.File
}

func NewPrint(fd int, debug *bool, verbose *bool, quiet *bool) *Print {
	p := &Print{}

	if fd != -1 {
		p.file = os.NewFile(uintptr(fd), "Custom")
	} else {
		p.file = os.NewFile(uintptr(syscall.Stdout), "/dev/stdout")
	}

	p.outputLevel = 1
	if *debug {
		p.outputLevel = 3
	} else if *verbose {
		p.outputLevel = 2
	} else if *quiet {
		p.outputLevel = 0
	}

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

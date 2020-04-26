package logger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/google/gopacket"
	"os"
	"syscall"
)

type JSON struct {
	outputLevel uint8
	file        *os.File
}

func NewJSON(fd int, debug *bool, verbose *bool, quiet *bool) *JSON {
	J := &JSON{}

	if fd != -1 {
		J.file = os.NewFile(uintptr(fd), "Custom")
	} else {
		J.file = os.NewFile(uintptr(syscall.Stdout), "/dev/stdout")
	}

	J.outputLevel = 1
	if *debug {
		J.outputLevel = 3
	} else if *verbose {
		J.outputLevel = 2
	} else if *quiet {
		J.outputLevel = 0
	}

	return J
}

type logStruct struct {
	Level   uint8
	Message string
}

func (J JSON) Debug(s string, a ...interface{}) {
	if J.outputLevel < 3 {
		return
	}

	log, _ := json.Marshal(&logStruct{
		Level:   3,
		Message: fmt.Sprintf(s, a...),
	})
	_, _ = fmt.Fprintln(J.file, string(log))
}

func (J JSON) Info(s string, a ...interface{}) {
	if J.outputLevel < 2 {
		return
	}

	log, _ := json.Marshal(&logStruct{
		Level:   2,
		Message: fmt.Sprintf(s, a...),
	})
	_, _ = fmt.Fprintln(J.file, string(log))
}

func (J JSON) Error(s string, a ...interface{}) {
	if J.outputLevel < 1 {
		return
	}

	log, _ := json.Marshal(&logStruct{
		Level:   1,
		Message: fmt.Sprintf(s, a...),
	})
	_, _ = fmt.Fprintln(J.file, string(log))
}

func (J JSON) Connection(net *gopacket.Flow, transport *gopacket.Flow, content *bytes.Buffer) {
	log, _ := json.Marshal(&logStruct{
		Level:   1,
		Message: "Connection",
	})
	_, _ = fmt.Fprintln(J.file, string(log))
}

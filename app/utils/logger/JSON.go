package logger

import (
	"breakerspace.cs.umd.edu/censorship/measurement/config"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/google/gopacket"
	"os"
)

type JSON struct {
	outputLevel uint8
	file        *os.File
}

func NewJSON(cfg *config.Config) *JSON {
	J := &JSON{}

	J.file, J.outputLevel = commonSetup(cfg)

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
		Level:   0,
		Message: fmt.Sprintf("%s %s: Censorship Detected\n%s", net, transport, content.Bytes()),
	})
	_, _ = fmt.Fprintln(J.file, string(log))
}

package logger

import (
	"breakerspace.cs.umd.edu/censorship/measurement/config"
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger/data"
	"encoding/json"
	"fmt"
	"github.com/Kkevsterrr/gopacket"
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

type logCollectedData struct {
	Net string
	Transport string
	Data []*data.Array
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

func (J JSON) Connection(net *gopacket.Flow, transport *gopacket.Flow, collectedData []*data.Array) {
	fmt.Printf("Hello")
	log, err := json.Marshal(&logCollectedData{
		Net: net.String(),
		Transport: transport.String(),
		Data: collectedData,
	})
	if err != nil {
		fmt.Printf("Error")
	}

	fmt.Printf("Hello2\n" + net.String() + transport.String())
	fmt.Printf(string(log) + "\n")
	_, _ = fmt.Fprintln(J.file, string(log))
}

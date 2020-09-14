package logger

import (
	"breakerspace.cs.umd.edu/censorship/measurement/config"
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger/data"
	"fmt"
	"github.com/Kkevsterrr/gopacket"
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

func (l *Print) Connection(net *gopacket.Flow, transport *gopacket.Flow, collectedData []*data.Array) {
	collectedDataString := make([]string, 0)

	for i, _ := range collectedData {
		oneCollectData := fmt.Sprintf("%s:%s\n", collectedData[i].Description, collectedData[i].Value)
		collectedDataString = append(collectedDataString, oneCollectData)
	}

	_, _ = fmt.Fprintf(l.file, "%s %s: Censorship Detected\n%s\n", net, transport, collectedDataString)
}

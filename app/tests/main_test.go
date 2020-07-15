package tests

import (
	"breakerspace.cs.umd.edu/censorship/measurement/config"
	"breakerspace.cs.umd.edu/censorship/measurement/connection"
	"breakerspace.cs.umd.edu/censorship/measurement/setup"
	"bytes"
	"io/ioutil"
	"os"
	"testing"
)

func TestRun(t *testing.T) {
	cfg := config.ReadConfig("resources/config.yml")

	// Truncate log file
	logFile, err := os.OpenFile(cfg.Logging.Output.File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
	if err != nil {
		t.Errorf("Error with truncating log file")
		t.FailNow()
	}
	logFile.Close()

	packetOptions, tcpOptions, cpuFile, memFile := setup.StartConfiguration(&cfg)

	connection.Run(packetOptions, tcpOptions)

	setup.EndConfiguration(cpuFile, memFile)

	contents, err := ioutil.ReadFile(cfg.Logging.Output.File)
	if err != nil {
		t.Errorf("Error reading log file")
		t.FailNow()
	}
	contents2, err := ioutil.ReadFile("resources/expected_test.log")
	if err != nil {
		t.Errorf("Error reading expected log file")
		t.FailNow()
	}
	if bytes.Compare(contents, contents2) != 0 {
		t.Errorf("Contents are not what was expected")
		t.FailNow()
	}

	_ = os.Remove(cfg.Logging.Output.File)
}

package main

import (
	"bytes"
	"golang.org/x/xerrors"
	"io/ioutil"
	"os"
	"testing"

	"breakerspace.cs.umd.edu/censorship/measurement/config"
	"breakerspace.cs.umd.edu/censorship/measurement/connection"
	"breakerspace.cs.umd.edu/censorship/measurement/setup"
)

func TestUnitRun1(t *testing.T) {
	cfg := config.ReadConfig("tests/test1/config.yml")

	err := mainHelper(&cfg, "tests/test1/expected_test.log", 0)

	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestUnitRun2(t *testing.T) {
	cfg := config.ReadConfig("tests/test2/config.yml")

	err := mainHelper(&cfg, "tests/test2/expected_test.log", 0)

	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestUnitRun3(t *testing.T) {
	cfg := config.ReadConfig("tests/test3/config.yml")

	err := mainHelper(&cfg, "tests/test3/expected_test.log", 297)

	if err != nil {
		t.Fatalf("%v", err)
	}
}

func mainHelper(cfg *config.Config, expectedLogFile string, lastBytes int) error {
	// Truncate log file
	logFile, err := os.OpenFile(cfg.Logging.Output.File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
	if err != nil {
		return xerrors.Errorf("Error with truncating log file")
	}
	logFile.Close()

	packetOptions, tcpOptions, cpuFile, memFile := setup.StartConfiguration(cfg)

	connection.Run(packetOptions, tcpOptions)

	setup.EndConfiguration(cfg, cpuFile, memFile)

	contents, err := ioutil.ReadFile(cfg.Logging.Output.File)
	if err != nil {
		return xerrors.Errorf("Error reading log file")
	}
	contents2, err := ioutil.ReadFile(expectedLogFile)
	if err != nil {
		return xerrors.Errorf("Error reading expected log file")
	}
	if lastBytes == 0 && !bytes.Equal(contents, contents2) {
		return xerrors.Errorf("Contents are not what was expected")
	} else if !bytes.Equal(contents[(len(contents)-lastBytes):], contents2[(len(contents2)-lastBytes):]) {
		return xerrors.Errorf("Contents are not what was expected: Last %d bytes", lastBytes)
	}

	_ = os.Remove(cfg.Logging.Output.File)

	return nil
}
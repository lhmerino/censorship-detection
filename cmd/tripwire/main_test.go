package main

import (
	"bytes"
	"io/ioutil"
	"os"
	"sort"
	"strings"
	"testing"
	"tripwire/config"
	"tripwire/parser"
	"tripwire/tcpstream"
	"tripwire/util/logger"
)

func TestIntegration(t *testing.T) {

	// Change working directory
	if err := os.Chdir("../../"); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		config string
		stderr string
		stdout string
	}{
		{name: "test1", config: "testdata/test1/config.yml", stderr: "testdata/test1/stderr.log", stdout: "testdata/test1/stdout.log"},
		{name: "test2", config: "testdata/test2/config.yml", stderr: "testdata/test2/stderr.log", stdout: "testdata/test2/stdout.log"},
		{name: "test3", config: "testdata/test3/config.yml", stderr: "testdata/test3/stderr.log", stdout: "testdata/test3/stdout.log"},
	}

	for _, test := range tests {

		// Reset metrics counters between tests
		parser.PacketsCount.Reset()
		tcpstream.StreamsCount.Reset()

		// Read config
		cfg := config.ReadConfig(test.config)

		// Redirect logging
		var actualStderr, actualStdout bytes.Buffer
		if cfg.Logger.Debug {
			logger.Debug.SetOutput(&actualStderr)
		}
		logger.Info.SetOutput(&actualStderr)
		cfg.StreamHandle = &actualStdout

		// Run Application
		run(cfg)

		// Compare output
		expectedStderr, err := ioutil.ReadFile(test.stderr)
		if err != nil {
			t.Fatalf("%v", err)
		}
		expectedStdout, err := ioutil.ReadFile(test.stdout)
		if err != nil {
			t.Fatalf("%v", err)
		}

		// Print order is non-deterministic, so compare sorted output lines
		if !compareSortedLines(expectedStderr, actualStderr.Bytes()) {
			t.Fatalf("Contents do not match for %v", test.name)
		}
		if !compareSortedLines(expectedStdout, actualStdout.Bytes()) {
			t.Fatalf("Contents do not match for %v", test.name)
		}
	}
}

func compareSortedLines(a, b []byte) bool {
	splitA, splitB := strings.Split(string(a), "\n"), strings.Split(string(b), "\n")
	sort.Strings(splitA)
	sort.Strings(splitB)
	return strings.Join(splitA, "\n") == strings.Join(splitB, "\n")
}

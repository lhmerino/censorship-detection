package main

import (
	"bytes"
	"flag"
	"io/ioutil"
	"os"
	"sort"
	"strings"
	"testing"
	"tripwire/pkg/logger"
	"tripwire/pkg/parser"
	"tripwire/pkg/tcpstream"
)

var update = flag.Bool("update", false, "update expected output ('golden') files")

// Regression tests to ensure that the tripwire output does not change
// unexpectedly.  Inspired by
// https://medium.com/@jarifibrahim/golden-files-why-you-should-use-them-47087ec994bf.
func TestIntegrationMain(t *testing.T) {

	// Change working directory
	if err := os.Chdir("../../"); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		config string
		stderr string
		stdout string
		sort   bool
	}{
		{name: "test1", config: "testdata/test1/config.yml", stderr: "testdata/test1/stderr.log", stdout: "testdata/test1/stdout.log", sort: false},
		{name: "test2", config: "testdata/test2/config.yml", stderr: "testdata/test2/stderr.log", stdout: "testdata/test2/stdout.log", sort: false},
		{name: "test3", config: "testdata/test3/config.yml", stderr: "testdata/test3/stderr.log", stdout: "testdata/test3/stdout.log", sort: true},
		{name: "test4", config: "testdata/test4/config.yml", stderr: "testdata/test4/stderr.log", stdout: "testdata/test4/stdout.log", sort: true},
		{name: "test5", config: "testdata/test5/config.yml", stderr: "testdata/test5/stderr.log", stdout: "testdata/test5/stdout.log", sort: true},
		{name: "test6", config: "testdata/test6/config.yml", stderr: "testdata/test6/stderr.log", stdout: "testdata/test6/stdout.log", sort: true},
		{name: "test7", config: "testdata/test7/config.yml", stderr: "testdata/test7/stderr.log", stdout: "testdata/test7/stdout.log", sort: true},
	}

	for _, test := range tests {

		// Reset metrics counters between tests
		parser.PacketsCount.Reset()
		tcpstream.StreamsCount.Reset()

		// Read config
		cfg := readConfig(test.config)

		// Redirect logging
		var stderrBuffer, stdoutBuffer bytes.Buffer
		if cfg.Logger.Debug {
			logger.Debug.SetOutput(&stderrBuffer)
		}
		logger.Info.SetOutput(&stderrBuffer)
		logger.StreamWriter = &stdoutBuffer

		// Run Application
		run(cfg)

		actualStderr := stderrBuffer.Bytes()
		actualStdout := stdoutBuffer.Bytes()

		if test.sort {
			// sort stdout
			tmp := strings.SplitAfter(stdoutBuffer.String(), "\n")
			sort.Strings(tmp)
			actualStdout = []byte(strings.Join(tmp, ""))
		}

		// Update tests if '--update' flag specified
		if *update {
			if err := ioutil.WriteFile(test.stderr, actualStderr, 0644); err != nil {
				t.Fatal(err)
			}
			if err := ioutil.WriteFile(test.stdout, actualStdout, 0644); err != nil {
				t.Fatal(err)
			}
		}

		// Get expected output from golden files
		expectedStderr, err := ioutil.ReadFile(test.stderr)
		if err != nil {
			t.Fatalf("%v", err)
		}
		expectedStdout, err := ioutil.ReadFile(test.stdout)
		if err != nil {
			t.Fatalf("%v", err)
		}

		// Compare output
		if !bytes.Equal(expectedStderr, actualStderr) {
			t.Fatalf("stderr does not match for %v", test.name)
		}
		if !bytes.Equal(expectedStdout, actualStdout) {
			t.Fatalf("stdout does not match for %v", test.name)
		}
	}

	// Reset working directory
	if err := os.Chdir("cmd/tripwire"); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkTripwire(b *testing.B) {
	// Change working directory
	if err := os.Chdir("../../"); err != nil {
		b.Fatal(err)
	}

	// Read config
	cfg := readConfig("testdata/bench1/config.yml")

	// Discard output
	logger.Info.SetOutput(ioutil.Discard)
	for i := 0; i < b.N; i++ {
		run(cfg)
	}

	// Reset working directory
	if err := os.Chdir("cmd/tripwire"); err != nil {
		b.Fatal(err)
	}
}

package main

import (
	"bytes"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"

	"github.com/kylelemons/godebug/diff"
)

// Run integration tests against tripwire executable in current directory
var executable = "bin/tripwire"

func TestIntegration(t *testing.T) {

	// Check that executable exists. If not, build with `go build -o bin/tripwire ./cmd/tripwire`
	_, err := os.Stat(executable)
	if os.IsNotExist(err) {
		t.Fatalf("%v does not exist", executable)
	} else if err != nil {
		t.Fatalf("%v", err)
	}

	tests := []struct {
		name      string
		config    string
		log       string
		expected  string
		lastBytes int
	}{
		{name: "test1", config: "testdata/test1/config.yml", log: "testdata/test1/test.log", expected: "testdata/test1/expected_test.log", lastBytes: 0},
		{name: "test2", config: "testdata/test2/config.yml", log: "testdata/test2/test.log", expected: "testdata/test2/expected_test.log", lastBytes: 0},
		{name: "test3", config: "testdata/test3/config.yml", log: "testdata/test3/test.log", expected: "testdata/test3/expected_test.log", lastBytes: 296},
	}

	for _, test := range tests {
		// truncate log file
		_ = os.Remove(test.log)

		err := exec.Command(executable, "-config_file", test.config).Run()
		if err != nil {
			t.Fatalf("%v", err)
		}
		actual, err := ioutil.ReadFile(test.log)
		if err != nil {
			t.Fatalf("%v", err)
		}
		expected, err := ioutil.ReadFile(test.expected)
		if err != nil {
			t.Fatalf("%v", err)
		}
		// compare only the last bytes of the files
		if test.lastBytes != 0 {
			actual = actual[len(actual)-test.lastBytes:]
			expected = expected[len(expected)-test.lastBytes:]
		}
		if !bytes.Equal(expected, actual) {
			t.Fatalf("Contents do not match for %v:\n%v", test.name, diff.Diff(string(expected), string(actual)))
		}

		// clean up
		_ = os.Remove(test.log)
	}

}

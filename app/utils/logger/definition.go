package logger

import (
	"breakerspace.cs.umd.edu/censorship/measurement/config"
	"bytes"
	"fmt"
	"github.com/google/gopacket"
	"os"
	"syscall"
)

var Logger Logging

type Logging interface {
	// Debug - arbitrary string
	Debug(s string, a ...interface{})

	// Info - arbitrary string
	Info(s string, a ...interface{})

	// Error - arbitrary string
	Error(s string, a ...interface{})

	// Connection - specific arguments
	Connection(net *gopacket.Flow, transport *gopacket.Flow, content *bytes.Buffer)
}

func SetupLogging(cfg *config.Config) {
	if cfg.Logging.Output.Fd < 0 && cfg.Logging.Output.File == "" {
		fmt.Printf("Logging Setup Failed - No output selected\n")
		os.Exit(3)
	} else if cfg.Logging.Output.Fd < 0 && cfg.Logging.Output.File != "" {
		// File Output
		fd, err := syscall.Open(cfg.Logging.Output.File, syscall.O_APPEND|syscall.O_CREAT|syscall.O_WRONLY, 644)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed to setup file logging: %d, %s\n", fd, err.Error())
			os.Exit(3)
		}
		cfg.Logging.Output.Fd = fd // Converting to Fd
	}
	// By default Fd Output

	if cfg.Logging.Type == "JSON" {
		Logger = NewJSON(cfg)
	} else if cfg.Logging.Type == "Print" {
		Logger = NewPrint(cfg)
	} else {
		fmt.Printf("[Logging Setup] Logger Type Unknown")
		os.Exit(4)
	}

	Logger.Info("Logger started up...")
}

func commonSetup(cfg *config.Config) (*os.File, uint8){
	var file *os.File
	if cfg.Logging.Output.Fd != -1 {
		file = os.NewFile(uintptr(cfg.Logging.Output.Fd), "Custom")
	} else {
		file = os.NewFile(uintptr(syscall.Stdout), "/dev/stdout")
	}

	var outputLevel uint8
	outputLevel = 1 // Default Info Level
	if cfg.Logging.Level.Debug {
		outputLevel = 3
	} else if cfg.Logging.Level.Verbose {
		outputLevel = 2
	} else if cfg.Logging.Level.Quiet {
		outputLevel = 0
	}

	return file, outputLevel
}

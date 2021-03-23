package logger

import (
	"io"
	"log"
	"os"
)

var (
	Debug        *log.Logger = log.New(os.Stderr, "DEBUG ", 0)
	Info         *log.Logger = log.New(os.Stderr, "INFO ", 0)
	StreamWriter io.Writer   = os.Stdout
)

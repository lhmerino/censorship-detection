package logger

import (
	"log"
	"os"
)

var (
	Debug = log.New(os.Stderr, "DEBUG ", 0)
	Info  = log.New(os.Stderr, "INFO ", 0)
)

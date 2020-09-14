package data

import (
	"strings"
)

// Data : Default structure for printing an array of strings
type Array struct {
	Description string // Describes what the values are about
	Value []string
}

func NewArray(description string, value []string) *Array {
	return &Array{Description: description, Value: value}
}

func (a *Array) String() string {
	return a.Description + ":" + strings.Join(a.Value, " |")
}
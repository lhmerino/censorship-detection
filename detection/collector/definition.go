package collector

import (
	"breakerspace.cs.umd.edu/censorship/measurement/detection/shared"
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger/data"
)

// Collector :
//	Defines the methods necessary for each struct that collects data
type Collector interface {
	shared.MainInterface
	shared.StreamInterface

	// GetData :
	//	Returns a string with the information collected throughout the stream
	GetData(someInterface interface{}) *data.Array
}

// Collectors : Global Instances of Collector
var Collectors []Collector
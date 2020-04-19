package shared

import "github.com/google/gopacket"

type SharedInterface interface {
	// Get the name of the specific type (censor, protocol)
	GetName() string

	// Determine if the new connection is relevant to the specific type (censor, protocol)
	RelevantNewConnection(net gopacket.Flow, transport gopacket.Flow) bool

	// Get basic identifiable information on specific type
	GetBasicInfo() string
}

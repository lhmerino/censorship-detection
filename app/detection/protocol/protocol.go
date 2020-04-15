package protocol

type Protocol interface {
	// Get the name of the protocol
	GetName() string

	// BPF filter for protocol
	BPFFilter() string
}

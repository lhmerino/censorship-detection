package protocol

var HTTP uint8 = 1

type Interface interface {
	ProcessDetection()
}

type Protocol struct {
	Interface
	kind uint8
}

func NewProtocol(kind uint8) *Protocol {
	return &Protocol{kind: kind}
}

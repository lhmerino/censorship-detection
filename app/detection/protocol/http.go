package protocol

import (
	"fmt"
	"github.com/google/gopacket"
)

type HTTP struct {
	Protocol

	port uint16
}

func NewHTTP() *HTTP {
	return &HTTP{port: 80}
}

func NewHTTPCustom(port uint16) *HTTP {
	return &HTTP{port: port}
}

func (h HTTP) GetName() string {
	return "HTTP"
}

func (h HTTP) GetBPFFilter() string {
	return fmt.Sprintf("tcp and port %d", h.port)
}

func (h HTTP) RelevantNewConnection(net gopacket.Flow, transport gopacket.Flow) bool {
	if transport.Dst().String() == fmt.Sprintf("%d", h.port) {
		return true
	}
	return false
}

func (h HTTP) GetBasicInfo() string {
	return fmt.Sprintf("HTTP on port %d", h.port)
}

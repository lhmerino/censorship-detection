package protocol

import (
	"fmt"
	"github.com/Kkevsterrr/gopacket"
)

type HTTP struct {
	Protocol

	port uint16
}

func NewHTTP(port uint16) *HTTP {
	return &HTTP{port: port}
}

func (h HTTP) GetName() string {
	return "HTTP"
}

func (h HTTP) GetBPFFilter() string {
	return fmt.Sprintf("tcp and port %d", h.port)
}

func (h HTTP) RelevantNewConnection(net gopacket.Flow, transport gopacket.Flow) bool {
	return transport.Dst().String() == fmt.Sprintf("%d", h.port)
}

func (h HTTP) GetBasicInfo() string {
	return fmt.Sprintf("HTTP on port %d", h.port)
}

package protocol

import (
	"fmt"
	"github.com/Kkevsterrr/gopacket"
)

// HTTPS protocol defined in https://tools.ietf.org/html/rfc5321
type HTTPS struct {
	Protocol

	port uint16 // port to monitor - Internal use only
}

func NewHTTPS(port uint16) *HTTPS {
	return &HTTPS{port: port}
}

func (p HTTPS) GetName() string {
	return "HTTPS"
}

func (p HTTPS) GetBPFFilter() string {
	return fmt.Sprintf("tcp and port %d", p.port)
}

func (p HTTPS) RelevantNewConnection(net gopacket.Flow, transport gopacket.Flow) bool {
	return transport.Dst().String() == fmt.Sprintf("%d", p.port)
}

func (p HTTPS) GetBasicInfo() string {
	return fmt.Sprintf("%s on port %d", p.GetName(), p.port)
}

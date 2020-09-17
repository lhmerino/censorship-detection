package protocol

import (
	"fmt"
	"github.com/Kkevsterrr/gopacket"
)

// DNS protocol defined in https://tools.ietf.org/html/rfc1035
type DNS struct {
	Protocol

	port uint16 // port to monitor - Internal use only
}

func NewDNS(port uint16) *DNS {
	return &DNS{port: port}
}

func (p DNS) GetName() string {
	return "DNS"
}

func (p DNS) GetBPFFilter() string {
	return fmt.Sprintf("tcp and port %d", p.port)
}

func (p DNS) RelevantNewConnection(net gopacket.Flow, transport gopacket.Flow) bool {
	if transport.Dst().String() == fmt.Sprintf("%d", p.port) {
		return true
	}
	return false
}

func (p DNS) GetBasicInfo() string {
	return fmt.Sprintf("%s on port %d", p.GetName(), p.port)
}

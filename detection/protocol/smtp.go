package protocol

import (
	"fmt"
	"github.com/Kkevsterrr/gopacket"
)

// SMTP protocol defined in https://tools.ietf.org/html/rfc5321
type SMTP struct {
	Protocol

	port uint16 // port to monitor - Internal use only
}

func NewSMTP(port uint16) *SMTP {
	return &SMTP{port: port}
}

func (p SMTP) GetName() string {
	return "SMTP"
}

func (p SMTP) GetBPFFilter() string {
	return fmt.Sprintf("tcp and port %d", p.port)
}

func (p SMTP) RelevantNewConnection(net gopacket.Flow, transport gopacket.Flow) bool {
	return transport.Dst().String() == fmt.Sprintf("%d", p.port)
}

func (p SMTP) GetBasicInfo() string {
	return fmt.Sprintf("%s on port %d", p.GetName(), p.port)
}

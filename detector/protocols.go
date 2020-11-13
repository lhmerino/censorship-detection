package detector

import (
	"github.com/Kkevsterrr/gopacket"
	"github.com/Kkevsterrr/gopacket/layers"
)

// http detects HTTP streams
type http struct{}

func newHTTP() *http {
	return &http{}
}

func (p *http) detected() bool {
	// TODO: process packets to detect protocol
	return true
}

// https detects HTTPS streams
type https struct{}

func newHTTPS() *https {
	return &https{}
}

func (p *https) detected() bool {
	// TODO: process packets to detect protocol
	return true
}

// ech detects HTTPS streams with the encrypted client hello extension
type ech struct {
	isECH bool
}

func newECH() *ech {
	return &ech{}
}

func (p *ech) processPacket(packet gopacket.Packet) {

	// check if packet is a TLS client hello with an ECH extension
	var clientHello *layers.TLSClientHello
	if packet.ApplicationLayer() != nil {
		var tls layers.TLS
		var decoded []gopacket.LayerType
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeTLS, &tls)
		err := parser.DecodeLayers(packet.ApplicationLayer().LayerContents(), &decoded)
		if err != nil {
			return
		}
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeTLS:
				if len(tls.Handshake) > 0 {
					hs := tls.Handshake[0]
					if hs.HandshakeType == 1 {
						clientHello = hs.ClientHello
					}
				}
			}
		}
	}
	if clientHello != nil {
		p.isECH = clientHello.EncryptedClientHello
	}
}

func (p *ech) detected() bool {
	return p.isECH
}

// smtp detects SMTP streams
type smtp struct{}

func newSMTP() *smtp {
	return &smtp{}
}

func (p *smtp) detected() bool {
	// TODO: process packets to detect protocol
	return true
}

// dns detects DNS streams
type dns struct{}

func newDNS() *dns {
	return &dns{}
}

func (p *dns) detected() bool {
	// TODO: process packets to detect protocol
	return true
}

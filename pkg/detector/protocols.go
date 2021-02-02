package detector

import (
	"bufio"
	"bytes"
	"net/http"
	"net/mail"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/Kkevsterrr/gopacket"
	"github.com/Kkevsterrr/gopacket/layers"
)

// http detects HTTP streams
type httpProtocol struct {
	isDetected bool
}

func newHTTPProtocol() *httpProtocol {
	return &httpProtocol{}
}

func (p *httpProtocol) detected() bool {
	return p.isDetected
}

func (p *httpProtocol) processPacket(packet gopacket.Packet) {
	if p.isDetected {
		// skip processing packet if already detected
		return
	}
	// Attempt to parse an HTTP request from the packet
	if app := packet.ApplicationLayer(); app != nil {
		buf := bufio.NewReader(bytes.NewReader(app.Payload()))
		_, err := http.ReadRequest(buf)
		if err != nil {
			return
		}
		p.isDetected = true
	}
}

// https detects HTTPS streams
type httpsProtocol struct {
	isDetected bool
}

func newHTTPSProtocol() *httpsProtocol {
	return &httpsProtocol{}
}

func (p *httpsProtocol) detected() bool {
	return p.isDetected
}

func (p *httpsProtocol) processPacket(packet gopacket.Packet) {
	if p.isDetected {
		// skip processing packet if already detected
		return
	}
	// Attempt to parse a TLS Client Hello from the packet
	if app := packet.ApplicationLayer(); app != nil {
		var tls layers.TLS
		var decoded []gopacket.LayerType
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeTLS, &tls)
		err := parser.DecodeLayers(app.LayerContents(), &decoded)
		if err != nil {
			return
		}
		for _, layerType := range decoded {
			if layerType == layers.LayerTypeTLS {
				if len(tls.Handshake) > 0 {
					hs := tls.Handshake[0]
					if hs.HandshakeType == 1 {
						p.isDetected = true
						return
					}
				}
			}
		}
	}
}

// smtp detects SMTP streams
type smtpProtocol struct {
	isDetected bool
}

func newSMTPProtocol() *smtpProtocol {
	return &smtpProtocol{}
}

func (p *smtpProtocol) detected() bool {
	return p.isDetected
}

func (p *smtpProtocol) processPacket(packet gopacket.Packet) {
	if p.isDetected {
		// skip processing packet if already detected
		return
	}
	// Attempt to parse a HTTP request from the packet
	if app := packet.ApplicationLayer(); app != nil {
		buf := bufio.NewReader(bytes.NewReader(app.Payload()))
		_, err := mail.ReadMessage(buf)
		if err != nil {
			return
		}
		p.isDetected = true
	}
}

// dns detects DNS streams
type dnsProtocol struct {
	isDetected bool
}

func newDNSProtocol() *dnsProtocol {
	return &dnsProtocol{}
}

func (p *dnsProtocol) detected() bool {
	return p.isDetected
}

func (p *dnsProtocol) processPacket(packet gopacket.Packet) {
	if p.isDetected {
		// skip processing packet if already detected
		return
	}
	// Attempt to parse a DNS message from the packet
	if app := packet.ApplicationLayer(); app != nil {
		var parser dnsmessage.Parser
		_, err := parser.Start(app.Payload())
		if err != nil {
			return
		}
		p.isDetected = true
	}
}

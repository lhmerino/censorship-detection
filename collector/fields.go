package collector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"tripwire/util/logger"

	"github.com/Kkevsterrr/gopacket"
	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/reassembly"
)

// ip collects stream src and dst IP addresses
type ip struct {
	net gopacket.Flow
}

func newIP(net gopacket.Flow) *ip {
	return &ip{net: net}
}

func (p *ip) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Src string `json:"src"`
		Dst string `json:"dst"`
	}{
		Src: p.net.Src().String(),
		Dst: p.net.Dst().String(),
	})
}

func (p *ip) String() string {
	return p.net.String()
}

// ipid collects packet IP IDs
type ipid struct {
	ipids []uint32
}

func newIPID() *ipid {
	return &ipid{}
}

func (p *ipid) processPacket(packet gopacket.Packet) {

	var id uint32

	if packet.NetworkLayer().LayerType() == layers.LayerTypeIPv4 {
		ipv4Layer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		id = uint32(ipv4Layer.Id)
	} else if packet.NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
		id = 1001 // Default value
		for _, layer := range packet.Layers() {
			if layer.LayerType() == layers.LayerTypeIPv6Fragment {
				ipv6FragmentLayer := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6Fragment)
				id = ipv6FragmentLayer.Identification
			}
		}
	} else {
		logger.Debug.Printf("Unknown Network Layer: %s", packet.NetworkLayer().LayerType().String())
	}

	p.ipids = append(p.ipids, id)
}

func (p *ipid) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.ipids)
}

func (p *ipid) String() string {
	if b, err := p.MarshalJSON(); err == nil {
		return string(b)
	}
	return "ERROR"
}

// ttl collects packet IP TTLs
func newTTL() *ttl {
	return &ttl{}
}

type ttl struct {
	ttls []uint8
}

func (p *ttl) processPacket(packet gopacket.Packet) {

	var ttl uint8

	if packet.NetworkLayer().LayerType() == layers.LayerTypeIPv4 {
		ipv4Layer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		ttl = ipv4Layer.TTL
	} else if packet.NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
		ipv6Layer := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		ttl = ipv6Layer.HopLimit
	} else {
		logger.Debug.Printf("Unknown Network Layer: %s", packet.NetworkLayer().LayerType().String())
	}

	p.ttls = append(p.ttls, ttl)
}

func (p *ttl) MarshalJSON() ([]byte, error) {
	// https://stackoverflow.com/questions/14177862/how-to-marshal-a-byte-uint8-array-as-json-array-in-go
	var result string
	if p.ttls == nil {
		result = "null"
	} else {
		result = strings.Join(strings.Fields(fmt.Sprintf("%d", p.ttls)), ",")
	}
	return []byte(result), nil
}

func (p *ttl) String() string {
	if b, err := p.MarshalJSON(); err == nil {
		return string(b)
	}
	return "ERROR"
}

// flags collects packet TCP flags
type flags struct {
	flags []string
}

func newFlags() *flags {
	return &flags{}
}

func (p *flags) processPacket(tcp *layers.TCP) {

	var flags string

	if tcp.FIN {
		flags += "F"
	}
	if tcp.SYN {
		flags += "S"
	}
	if tcp.RST {
		flags += "R"
	}
	if tcp.PSH {
		flags += "P"
	}
	if tcp.ACK {
		flags += "A"
	}
	if tcp.URG {
		flags += "U"
	}
	if tcp.CWR {
		flags += "C"
	}
	if tcp.ECE {
		flags += "E"
	}
	if tcp.NS {
		flags += "N"
	}

	p.flags = append(p.flags, flags)
}

func (p *flags) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.flags)
}

func (p *flags) String() string {
	if b, err := p.MarshalJSON(); err == nil {
		return string(b)
	}
	return "ERROR"
}

// ports collects packet src and dst TCP ports
type ports struct {
	srcPorts []layers.TCPPort
	dstPorts []layers.TCPPort
}

func newPorts() *ports {
	return &ports{}
}

func (p *ports) processPacket(tcp *layers.TCP) {
	p.srcPorts = append(p.srcPorts, tcp.SrcPort)
	p.dstPorts = append(p.dstPorts, tcp.DstPort)
}

func (p *ports) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Src []layers.TCPPort `json:"src"`
		Dst []layers.TCPPort `json:"dst"`
	}{
		Src: p.srcPorts,
		Dst: p.dstPorts,
	})
}

func (p *ports) String() string {
	var elems []string
	for i := range p.srcPorts {
		elems = append(elems, fmt.Sprintf("%s->%s", p.srcPorts[i], p.dstPorts[i]))
	}
	return strings.Join(elems, ", ")
}

// seqnum collects packet TCP sequence numbers
type seqnum struct {
	seq []uint32
	ack []uint32
}

func newSeqNum() *seqnum {
	return &seqnum{}
}

func (p *seqnum) processPacket(tcp *layers.TCP) {
	p.seq = append(p.seq, tcp.Seq)
	p.ack = append(p.ack, tcp.Ack)
}

func (p *seqnum) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Seq []uint32 `json:"seq"`
		Ack []uint32 `json:"ack"`
	}{
		Seq: p.seq,
		Ack: p.ack,
	})
}

func (p *seqnum) String() string {
	var elems []string
	for i := range p.seq {
		elems = append(elems, fmt.Sprintf("%d-%d", p.seq[i], p.ack[i]))
	}
	return strings.Join(elems, ", ")
}

// payload collects reassembled application-layer payloads
type payload struct {
	clientMaxLength int
	serverMaxLength int
	client          bytes.Buffer
	server          bytes.Buffer
}

func newPayload(cliLen, srvLen int) *payload {
	return &payload{clientMaxLength: cliLen, serverMaxLength: srvLen}
}

func (p *payload) processReassembled(sg reassembly.ScatterGather) {

	dir, _, _, _ := sg.Info()
	length, _ := sg.Lengths()

	payload := sg.Fetch(length)
	if dir == reassembly.TCPDirClientToServer {
		currLength := p.client.Len()
		if length+currLength >= p.clientMaxLength {
			length = p.clientMaxLength - currLength
		}
		p.client.Write(payload[:length])
	} else {
		currLength := p.client.Len()
		if length+currLength >= p.serverMaxLength {
			length = p.serverMaxLength - currLength
		}
		p.server.Write(payload[:length])
	}
}

func (p *payload) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Client []byte `json:"cli"`
		Server []byte `json:"srv"`
	}{
		Client: p.client.Bytes(),
		Server: p.server.Bytes(),
	})
}

func (p *payload) String() string {
	return fmt.Sprintf("client: %x; server: %x", p.client.Bytes(), p.server.Bytes())
}

// sni collects TLS server name extensions
type sni struct {
	sni string
}

func newSNI() *sni {
	return &sni{}
}

func (p *sni) String() string {
	return p.sni
}

func (p *sni) processPacket(packet gopacket.Packet) {

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
		p.sni = clientHello.ServerName
	}
}

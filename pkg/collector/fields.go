package collector

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"tripwire/pkg/util/logger"

	"github.com/Kkevsterrr/gopacket"
	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/reassembly"
)

// ipCollector collects stream src and dst IP addresses
type ipCollector gopacket.Flow

func newIPCollector(net gopacket.Flow, truncate bool) *ipCollector {
	// Truncate IPv4 addresses to /24 and IPv6 addresses to /48
	if truncate {
		switch net.EndpointType() {
		case layers.EndpointIPv4:
			src, dst := net.Src().Raw(), net.Dst().Raw()
			if len(src) != len(dst) || len(src) != 4 {
				logger.Debug.Printf("Invalid EndpointIPv4 byte length: src: %v, dst: %v", len(src), len(dst))
				return nil
			}
			// clear last 8 bits of IPv4 address
			src[3], dst[3] = 0, 0
			net = gopacket.NewFlow(layers.EndpointIPv4, src, dst)
		case layers.EndpointIPv6:
			src, dst := net.Src().Raw(), net.Dst().Raw()
			if len(src) != len(dst) || len(src) != 16 {
				logger.Debug.Printf("Invalid EndpointIPv6 byte length: src: %v, dst: %v", len(src), len(dst))
				return nil
			}
			// clear last 80 bits of IPv6 address
			for i := 0; i < 10; i++ {
				src[6+i], dst[6+i] = 0, 0
			}
			net = gopacket.NewFlow(layers.EndpointIPv6, src, dst)
		default:
			logger.Debug.Printf("Unknown Endpoint Type: %v", net.EndpointType())
			return nil
		}
	}
	return (*ipCollector)(&net)
}

func (p *ipCollector) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Src string `json:"src"`
		Dst string `json:"dst"`
	}{
		Src: (*gopacket.Flow)(p).Src().String(),
		Dst: (*gopacket.Flow)(p).Dst().String(),
	})
}

func (p *ipCollector) String() string {
	return (*gopacket.Flow)(p).String()
}

// ipidCollector collects packet IP IDs
type ipidCollector []uint32

func newIPIDCollector() *ipidCollector {
	return new(ipidCollector)
}

func (p *ipidCollector) processPacket(packet gopacket.Packet) {
	var ipid uint32

	switch packet.NetworkLayer().LayerType() {
	case layers.LayerTypeIPv4:
		ipv4Layer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		ipid = uint32(ipv4Layer.Id)
	case layers.LayerTypeIPv6:
		ipid = 1001 // Default value
		for _, layer := range packet.Layers() {
			if layer.LayerType() == layers.LayerTypeIPv6Fragment {
				ipv6FragmentLayer := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6Fragment)
				ipid = ipv6FragmentLayer.Identification
			}
		}
	default:
		logger.Debug.Printf("Unknown Network Layer: %s", packet.NetworkLayer().LayerType().String())
	}

	*p = append(*p, ipid)
}

func (p *ipidCollector) MarshalJSON() ([]byte, error) {
	return json.Marshal(*p)
}

func (p *ipidCollector) String() string {
	return strings.Join(strings.Fields(fmt.Sprintf("%d", *p)), ",")
}

// directionCollector collects the packet tcp flow direction
// true: client->server; false: server->client
type directionCollector []bool

func newDirectionCollector() *directionCollector {
	return new(directionCollector)
}

func (p *directionCollector) processPacket(dir reassembly.TCPFlowDirection) {
	*p = append(*p, bool(dir))
}

func (p *directionCollector) MarshalJSON() ([]byte, error) {
	return json.Marshal(*p)
}

func (p *directionCollector) String() string {
	return strings.Join(strings.Fields(fmt.Sprintf("%t", *p)), ",")
}

// timestampCollector collects the packet timestamps in microseconds. The first
// packet timestamp is set to 0 and all other timestamps are set relative to
// the first.
type timestampCollector struct {
	startUs     int64
	timestampUs []int64
}

func newTimestampCollector() *timestampCollector {
	return &timestampCollector{}
}

func (p *timestampCollector) processPacket(ci gopacket.CaptureInfo) {
	pktUs := ci.Timestamp.UnixNano() / 1000
	if p.startUs == 0 {
		p.startUs = pktUs
	}
	p.timestampUs = append(p.timestampUs, pktUs-p.startUs)
}

func (p *timestampCollector) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.timestampUs)
}

func (p *timestampCollector) String() string {
	return strings.Join(strings.Fields(fmt.Sprintf("%d", p.timestampUs)), ",")
}

// ttlCollector collects packet IP TTLs
type ttlCollector []uint8

func newTTLCollector() *ttlCollector {
	return new(ttlCollector)
}

func (p *ttlCollector) processPacket(packet gopacket.Packet) {
	var ttl uint8

	switch packet.NetworkLayer().LayerType() {
	case layers.LayerTypeIPv4:
		ipv4Layer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		ttl = ipv4Layer.TTL
	case layers.LayerTypeIPv6:
		ipv6Layer := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		ttl = ipv6Layer.HopLimit
	default:
		logger.Debug.Printf("Unknown Network Layer: %s", packet.NetworkLayer().LayerType().String())
	}

	*p = append(*p, ttl)
}

func (p *ttlCollector) MarshalJSON() ([]byte, error) {
	// https://stackoverflow.com/questions/14177862/how-to-marshal-a-byte-uint8-array-as-json-array-in-go
	return []byte(p.String()), nil
}

func (p *ttlCollector) String() string {
	return strings.Join(strings.Fields(fmt.Sprintf("%d", *p)), ",")
}

// flagCollector collects packet TCP flags
type flagCollector []string

func newFlagCollector() *flagCollector {
	return new(flagCollector)
}

func (p *flagCollector) processPacket(tcp *layers.TCP) {
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

	*p = append(*p, flags)
}

func (p *flagCollector) MarshalJSON() ([]byte, error) {
	return json.Marshal(*p)
}

func (p *flagCollector) String() string {
	return strings.Join(strings.Fields(fmt.Sprintf("%q", *p)), ",")
}

// portCollector collects packet src and dst TCP ports
type portCollector gopacket.Flow

func newPortCollector(transport gopacket.Flow) *portCollector {
	if transport.EndpointType() != layers.EndpointTCPPort {
		logger.Debug.Printf("Unknown Endpoint Type: %v", transport.EndpointType())
		return nil
	}
	return (*portCollector)(&transport)
}

func (p *portCollector) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Src string `json:"src"`
		Dst string `json:"dst"`
	}{
		Src: (*gopacket.Flow)(p).Src().String(),
		Dst: (*gopacket.Flow)(p).Dst().String(),
	})
}

func (p *portCollector) String() string {
	return (*gopacket.Flow)(p).String()
}

// seqnumCollector collects packet TCP sequence and acknowledgement numbers
type seqnumCollector struct {
	seq []uint32
	ack []uint32
}

func newSeqNumCollector() *seqnumCollector {
	return &seqnumCollector{}
}

func (p *seqnumCollector) processPacket(tcp *layers.TCP) {
	p.seq = append(p.seq, tcp.Seq)
	p.ack = append(p.ack, tcp.Ack)
}

func (p *seqnumCollector) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Seq []uint32 `json:"seq"`
		Ack []uint32 `json:"ack"`
	}{
		Seq: p.seq,
		Ack: p.ack,
	})
}

func (p *seqnumCollector) String() string {
	seqStr := strings.Join(strings.Fields(fmt.Sprintf("%d", p.seq)), ",")
	ackStr := strings.Join(strings.Fields(fmt.Sprintf("%d", p.ack)), ",")
	return fmt.Sprintf("seq: %s; ack: %s", seqStr, ackStr)
}

// payloadCollector collects reassembled application-layer payloads
type payloadCollector struct {
	clientMaxLength int
	serverMaxLength int
	client          bytes.Buffer
	server          bytes.Buffer
}

func newPayloadCollector(cliLen, srvLen int) *payloadCollector {
	return &payloadCollector{clientMaxLength: cliLen, serverMaxLength: srvLen}
}

func (p *payloadCollector) processReassembled(dir reassembly.TCPFlowDirection, length int, payload []byte) {
	if dir == reassembly.TCPDirClientToServer {
		currLength := p.client.Len()
		if length+currLength >= p.clientMaxLength {
			length = p.clientMaxLength - currLength
		}
		p.client.Write(payload[:length])
	} else {
		currLength := p.server.Len()
		if length+currLength >= p.serverMaxLength {
			length = p.serverMaxLength - currLength
		}
		p.server.Write(payload[:length])
	}
}

func (p *payloadCollector) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Client []byte `json:"cli"`
		Server []byte `json:"srv"`
	}{
		Client: p.client.Bytes(),
		Server: p.server.Bytes(),
	})
}

func (p *payloadCollector) String() string {
	return fmt.Sprintf("client: %x; server: %x", p.client.Bytes(), p.server.Bytes())
}

// hostCollector collects HTTP Host headers
type hostCollector string

func newHostCollector() *hostCollector {
	return new(hostCollector)
}

func (p *hostCollector) processPacket(packet gopacket.Packet) {
	if app := packet.ApplicationLayer(); app != nil {
		buf := bufio.NewReader(bytes.NewReader(app.Payload()))
		req, err := http.ReadRequest(buf)
		if err != nil {
			return
		}
		*p = hostCollector(req.Host)
	}
}

func (p *hostCollector) String() string {
	return string(*p)
}

func (p *hostCollector) MarshalJSON() ([]byte, error) {
	return json.Marshal(*p)
}

// sniCollector collects the TLS server name extension value
type sniCollector string

func newSNICollector() *sniCollector {
	return new(sniCollector)
}

func (p *sniCollector) String() string {
	return string(*p)
}

func (p *sniCollector) MarshalJSON() ([]byte, error) {
	return json.Marshal(*p)
}

func (p *sniCollector) processPacket(packet gopacket.Packet) {
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
		*p = sniCollector(clientHello.ServerName)
	}
}

// tlsExtensionsCollector collects TLS client hello extensions
type tlsExtensionsCollector []uint16

func newTLSExtensionsCollector() *tlsExtensionsCollector {
	return new(tlsExtensionsCollector)
}

func (p *tlsExtensionsCollector) String() string {
	return strings.Join(strings.Fields(fmt.Sprintf("%d", *p)), ",")
}

func (p *tlsExtensionsCollector) MarshalJSON() ([]byte, error) {
	return json.Marshal(*p)
}

func (p *tlsExtensionsCollector) processPacket(packet gopacket.Packet) {
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
						break
					}
				}
			}
		}
	}
	if clientHello != nil {
		*p = tlsExtensionsCollector(clientHello.Extensions)
	}
}

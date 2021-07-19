package detector

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"tripwire/pkg/config"

	"github.com/Kkevsterrr/gopacket"
	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/reassembly"
)

type ProtocolType int

const (
	ProtocolAny ProtocolType = iota
	ProtocolHTTP
	ProtocolHTTPS
	ProtocolDNS
	ProtocolSMTP
)

var protocolMap = map[string]ProtocolType{
	"any":   ProtocolAny,
	"http":  ProtocolHTTP,
	"https": ProtocolHTTPS,
	"dns":   ProtocolDNS,
	"smtp":  ProtocolSMTP,
}

type SignatureType int

const (
	SignatureAny SignatureType = iota
	SignatureRSTACKs
	SignatureWIN
	SignatureTime
	SignaturePacketCount
)

var signatureMap = map[string]SignatureType{
	"any":         SignatureAny,
	"rstacks":     SignatureRSTACKs,
	"win":         SignatureWIN,
	"time":        SignatureTime,
	"packetcount": SignaturePacketCount,
}

type DetectorFactory interface {
	Label() string
	RelevantToConnection(net, transport gopacket.Flow) bool
	NewDetector(net, transport gopacket.Flow, tcp *layers.TCP) Detector
}

type Detector interface {
	fmt.Stringer
	json.Marshaler
	Label() string // metrics label
	ProcessPacket(packet gopacket.Packet, tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection)
	ProcessReassembled(sg *reassembly.ScatterGather, ac *reassembly.AssemblerContext, dir reassembly.TCPFlowDirection)
	ProtocolDetected() bool  // whether or not protocol is detected
	SignatureDetected() bool // whether or not signature detects disruption
}

type detectorFactory struct {
	label     string
	port      uint16
	protocol  ProtocolType
	signature SignatureType

	// extra options
	timeThresholdMs int // time detector
	packetThreshold int // packetCount detector
}

type detector struct {
	// label for metrics
	label string

	// protocols
	anyProtocol bool
	http        *httpProtocol
	https       *httpsProtocol
	dns         *dnsProtocol
	smtp        *smtpProtocol

	// signatures
	anySignature bool
	rstacks      *rstacksSignature
	win          *windowSignature
	time         *TimeSignature
	packetCount  *PacketCountSignature
}

func NewDetectorFactory(cfg config.DetectorConfig) (DetectorFactory, error) {
	var f detectorFactory

	var ok bool
	if f.protocol, ok = protocolMap[strings.ToLower(cfg.Protocol)]; !ok {
		return nil, fmt.Errorf("[Config] Invalid Protocol %s\n", cfg.Protocol)
	}
	if f.signature, ok = signatureMap[strings.ToLower(cfg.Signature)]; !ok {
		return nil, fmt.Errorf("[Config] Invalid Signature %s\n", cfg.Signature)
	}

	f.label = cfg.Name
	f.port = cfg.Port
	f.timeThresholdMs = cfg.TimeThresholdMs
	f.packetThreshold = cfg.PacketThreshold

	return &f, nil
}

func (f *detectorFactory) NewDetector(net, transport gopacket.Flow, tcp *layers.TCP) Detector {
	var d detector
	d.label = f.label

	switch f.protocol {
	case ProtocolHTTP:
		d.http = newHTTPProtocol()
	case ProtocolHTTPS:
		d.https = newHTTPSProtocol()
	case ProtocolDNS:
		d.dns = newDNSProtocol()
	case ProtocolSMTP:
		d.smtp = newSMTPProtocol()
	case ProtocolAny:
		d.anyProtocol = true
	}

	switch f.signature {
	case SignatureRSTACKs:
		d.rstacks = newRSTACKsSignature()
	case SignatureWIN:
		d.win = newWindowSignature()
	case SignatureTime:
		d.time = newTimeSignature(f.timeThresholdMs)
	case SignaturePacketCount:
		d.packetCount = newPacketCountSignature(f.packetThreshold)
	case SignatureAny:
		d.anySignature = true
	}
	return &d
}

func (f *detectorFactory) Label() string {
	return f.label
}

func (f *detectorFactory) RelevantToConnection(net, transport gopacket.Flow) bool {
	if transport.EndpointType() == layers.EndpointTCPPort {
		return f.port == binary.BigEndian.Uint16(transport.Dst().Raw())
	}
	return false
}

func (d *detector) String() string {
	return d.label
}

func (d *detector) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.label)
}

func (d *detector) Label() string {
	return d.label
}

func (d *detector) ProcessPacket(packet gopacket.Packet, tcp *layers.TCP,
	ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection) {
	// protocols
	if d.http != nil {
		d.http.processPacket(packet)
	}
	if d.https != nil {
		d.https.processPacket(packet)
	}
	if d.dns != nil {
		d.dns.processPacket(packet)
	}
	if d.smtp != nil {
		d.smtp.processPacket(packet)
	}

	// signatures
	if d.rstacks != nil {
		d.rstacks.processPacket(tcp, dir)
	}
	if d.win != nil {
		d.win.processPacket(tcp, dir)
	}
	if d.time != nil {
		d.time.processPacket(tcp, ci, dir)
	}
	if d.packetCount != nil {
		d.packetCount.processPacket(tcp, dir)
	}
}

func (d *detector) ProcessReassembled(sg *reassembly.ScatterGather,
	ac *reassembly.AssemblerContext, dir reassembly.TCPFlowDirection) {
	// no current signatures process the reassembled payload
}

func (d *detector) ProtocolDetected() (detected bool) {
	if d.anyProtocol {
		return true
	}
	if d.http != nil && d.http.detected() {
		detected = true
	}
	if d.https != nil && d.https.detected() {
		detected = true
	}
	if d.dns != nil && d.dns.detected() {
		detected = true
	}
	if d.smtp != nil && d.smtp.detected() {
		detected = true
	}
	return
}

func (d *detector) SignatureDetected() (detected bool) {
	if d.anySignature {
		return true
	}
	if d.rstacks != nil && d.rstacks.detected() {
		detected = true
	}
	if d.win != nil && d.win.detected() {
		detected = true
	}
	if d.time != nil && d.time.detected() {
		detected = true
	}
	if d.packetCount != nil && d.packetCount.detected() {
		detected = true
	}
	return
}

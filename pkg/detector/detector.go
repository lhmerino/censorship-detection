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

type HeuristicType int

const (
	HeuristicAny HeuristicType = iota
	HeuristicRSTACKs
	HeuristicWIN
)

var heuristicMap = map[string]HeuristicType{
	"any":     HeuristicAny,
	"rstacks": HeuristicRSTACKs,
	"win":     HeuristicWIN,
}

type DetectorFactory interface {
	Label() string
	RelevantToConnection(net, transport gopacket.Flow) bool
	NewDetector(net, transport gopacket.Flow, tcp *layers.TCP) Detector
	BPFFilter() string
}

type Detector interface {
	fmt.Stringer
	json.Marshaler
	Label() string // metrics label
	ProcessPacket(packet gopacket.Packet, tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection)
	ProcessReassembled(sg *reassembly.ScatterGather, ac *reassembly.AssemblerContext, dir reassembly.TCPFlowDirection)
	ProtocolDetected() bool  // whether or not protocol is detected
	HeuristicDetected() bool // whether or not heuristic detects disruption
}

type detectorFactory struct {
	label     string
	port      uint16
	protocol  ProtocolType
	heuristic HeuristicType
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

	// heuristics
	anyHeuristic bool
	rstacks      *rstacksHeuristic
	win          *windowHeuristic
}

func NewDetectorFactory(cfg config.DetectorConfig) (DetectorFactory, error) {
	var f detectorFactory

	f.label = cfg.Name
	if f.label == "" {
		f.label = fmt.Sprintf("%s_%d_%s", strings.ToLower(cfg.Protocol), cfg.Port, strings.ToLower(cfg.Heuristic))
	}

	f.port = cfg.Port

	var ok bool
	if f.protocol, ok = protocolMap[strings.ToLower(cfg.Protocol)]; !ok {
		return nil, fmt.Errorf("[Config] Invalid Protocol %s\n", cfg.Protocol)
	}
	if f.heuristic, ok = heuristicMap[strings.ToLower(cfg.Heuristic)]; !ok {
		return nil, fmt.Errorf("[Config] Invalid Heuristic %s\n", cfg.Heuristic)
	}

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

	switch f.heuristic {
	case HeuristicRSTACKs:
		d.rstacks = newRSTACKsHeuristic()
	case HeuristicWIN:
		d.win = newWindowHeuristic()
	case HeuristicAny:
		d.anyHeuristic = true
	}
	return &d
}

func (f *detectorFactory) Label() string {
	return f.label
}

func (f *detectorFactory) BPFFilter() string {
	return fmt.Sprintf("tcp and port %d", f.port)
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

	// heuristics
	if d.rstacks != nil {
		d.rstacks.processPacket(tcp, dir)
	}
	if d.win != nil {
		d.win.processPacket(tcp, dir)
	}
}

func (d *detector) ProcessReassembled(sg *reassembly.ScatterGather,
	ac *reassembly.AssemblerContext, dir reassembly.TCPFlowDirection) {
	// no current heuristics process the reassembled payload
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

func (d *detector) HeuristicDetected() (detected bool) {
	if d.anyHeuristic {
		return true
	}
	if d.rstacks != nil && d.rstacks.detected() {
		detected = true
	}
	if d.win != nil && d.win.detected() {
		detected = true
	}
	return
}

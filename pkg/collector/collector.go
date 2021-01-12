package collector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"tripwire/pkg/config"

	"github.com/Kkevsterrr/gopacket"
	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/reassembly"
)

type CollectorFactory interface {
	NewCollector(net, transport gopacket.Flow, tcp *layers.TCP) Collector
}

type Collector interface {
	fmt.Stringer
	json.Marshaler

	ProcessReassembled(sg reassembly.ScatterGather, ac reassembly.AssemblerContext, dir reassembly.TCPFlowDirection)
	ProcessPacket(packet gopacket.Packet, tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection)
}

type FieldType int

const (
	FieldIP FieldType = iota
	FieldPorts
	FieldDirection
	FieldTimestamp
	FieldIPID
	FieldTTL
	FieldFlags
	FieldPayload
	FieldSeqNum
	FieldSNI
	FieldHost
)

var fieldMap = map[string]FieldType{
	"ip":        FieldIP,
	"ports":     FieldPorts,
	"direction": FieldDirection,
	"timestamp": FieldTimestamp,
	"ipid":      FieldIPID,
	"ttl":       FieldTTL,
	"flags":     FieldFlags,
	"payload":   FieldPayload,
	"seqnum":    FieldSeqNum,
	"sni":       FieldSNI,
	"host":      FieldHost,
}

type collectorFactory struct {
	fields []FieldType

	truncateIPs            bool
	maxPacketCount         int
	maxClientPayloadLength int
	maxServerPayloadLength int
}

type collector struct {
	packetCount, maxPacketCount int
	// Enabled features are non-nil
	ip        *ipCollector
	ports     *portCollector
	direction *directionCollector
	timestamp *timestampCollector
	ipid      *ipidCollector
	ttl       *ttlCollector
	flags     *flagCollector
	payload   *payloadCollector
	seqnum    *seqnumCollector
	sni       *sniCollector
	host      *hostCollector
}

func NewCollectorFactory(cfg config.CollectorConfig) (CollectorFactory, error) {
	var f collectorFactory
	for _, field := range cfg.Fields {
		fieldType, ok := fieldMap[strings.ToLower(field)]
		if !ok {
			return nil, fmt.Errorf("[Config] Invalid Collector Field: %s", field)
		}
		f.fields = append(f.fields, fieldType)
	}
	f.truncateIPs = cfg.TruncateIPs
	f.maxPacketCount = cfg.MaxPacketCount
	if f.maxPacketCount == 0 {
		f.maxPacketCount = 25
	}
	f.maxClientPayloadLength = cfg.MaxClientPayloadLength
	f.maxServerPayloadLength = cfg.MaxServerPayloadLength

	return &f, nil
}

func (f *collectorFactory) NewCollector(net, transport gopacket.Flow, tcp *layers.TCP) Collector {
	var c collector
	c.maxPacketCount = f.maxPacketCount
	for _, field := range f.fields {
		switch field {
		case FieldIP:
			c.ip = newIPCollector(net, f.truncateIPs)
		case FieldPorts:
			c.ports = newPortCollector(transport)
		case FieldDirection:
			c.direction = newDirectionCollector()
		case FieldTimestamp:
			c.timestamp = newTimestampCollector()
		case FieldIPID:
			c.ipid = newIPIDCollector()
		case FieldTTL:
			c.ttl = newTTLCollector()
		case FieldFlags:
			c.flags = newFlagCollector()
		case FieldSeqNum:
			c.seqnum = newSeqNumCollector()
		case FieldPayload:
			c.payload = newPayloadCollector(f.maxClientPayloadLength, f.maxServerPayloadLength)
		case FieldSNI:
			c.sni = newSNICollector()
		case FieldHost:
			c.host = newHostCollector()
		}
	}
	return &c
}

func (c *collector) ProcessPacket(packet gopacket.Packet, tcp *layers.TCP,
	ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection) {
	c.packetCount++
	if c.packetCount > c.maxPacketCount {
		return
	}
	if c.direction != nil {
		c.direction.processPacket(dir)
	}
	if c.timestamp != nil {
		c.timestamp.processPacket(ci)
	}
	if c.ipid != nil {
		c.ipid.processPacket(packet)
	}
	if c.ttl != nil {
		c.ttl.processPacket(packet)
	}
	if c.flags != nil {
		c.flags.processPacket(tcp)
	}
	if c.seqnum != nil {
		c.seqnum.processPacket(tcp)
	}
	if c.sni != nil {
		c.sni.processPacket(packet)
	}
}

func (c *collector) ProcessReassembled(sg reassembly.ScatterGather,
	ac reassembly.AssemblerContext, dir reassembly.TCPFlowDirection) {

	length, _ := sg.Lengths()
	payload := sg.Fetch(length)

	if c.payload != nil {
		c.payload.processReassembled(dir, length, payload)
	}
	if c.host != nil {
		c.host.processReassembled(dir, length, payload)
	}
}

func (c *collector) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		IP        *ipCollector        `json:"ip,omitempty"`
		Ports     *portCollector      `json:"ports,omitempty"`
		Direction *directionCollector `json:"direction,omitempty"`
		Timestamp *timestampCollector `json:"timestamp,omitempty"`
		IPID      *ipidCollector      `json:"ipid,omitempty"`
		TTL       *ttlCollector       `json:"ttl,omitempty"`
		Flags     *flagCollector      `json:"flags,omitempty"`
		SeqNum    *seqnumCollector    `json:"seqnum,omitempty"`
		Payload   *payloadCollector   `json:"payload,omitempty"`
		SNI       *sniCollector       `json:"sni,omitempty"`
		Host      *hostCollector      `json:"host,omitempty"`
	}{
		IP:        c.ip,
		Ports:     c.ports,
		Direction: c.direction,
		Timestamp: c.timestamp,
		IPID:      c.ipid,
		TTL:       c.ttl,
		Flags:     c.flags,
		SeqNum:    c.seqnum,
		Payload:   c.payload,
		SNI:       c.sni,
		Host:      c.host,
	})
}

func (c *collector) String() string {
	var b bytes.Buffer
	if c.ip != nil {
		b.WriteString(fmt.Sprintf("  IP: %s\n", c.ip))
	}
	if c.ports != nil {
		b.WriteString(fmt.Sprintf("  Ports: %s\n", c.ports))
	}
	if c.direction != nil {
		b.WriteString(fmt.Sprintf("  Direction: %s\n", c.direction))
	}
	if c.timestamp != nil {
		b.WriteString(fmt.Sprintf("  Timestamp: %s\n", c.timestamp))
	}
	if c.ipid != nil {
		b.WriteString(fmt.Sprintf("  IPID: %s\n", c.ipid))
	}
	if c.ttl != nil {
		b.WriteString(fmt.Sprintf("  TTL: %s\n", c.ttl))
	}
	if c.flags != nil {
		b.WriteString(fmt.Sprintf("  Flags: %s\n", c.flags))
	}
	if c.seqnum != nil {
		b.WriteString(fmt.Sprintf("  SeqNum: %s\n", c.seqnum))
	}
	if c.payload != nil {
		b.WriteString(fmt.Sprintf("  Payload: %s\n", c.payload))
	}
	if c.sni != nil {
		b.WriteString(fmt.Sprintf("  SNI: %s\n", c.sni))
	}
	if c.host != nil {
		b.WriteString(fmt.Sprintf("  Host: %s\n", c.host))
	}
	return b.String()
}

package collector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"tripwire/config"

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

	ProcessReassembled(sg reassembly.ScatterGather, ac reassembly.AssemblerContext)
	ProcessPacket(packet gopacket.Packet, tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection)
}

type FieldType int

const (
	FieldIP FieldType = iota
	FieldIPID
	FieldTTL
	FieldFlags
	FieldPayload
	FieldPorts
	FieldSeqNum
	FieldSNI
)

var fieldMap = map[string]FieldType{
	"ip":      FieldIP,
	"ipid":    FieldIPID,
	"ttl":     FieldTTL,
	"flags":   FieldFlags,
	"payload": FieldPayload,
	"ports":   FieldPorts,
	"seqnum":  FieldSeqNum,
	"sni":     FieldSNI,
}

type collectorFactory struct {
	fields []FieldType

	clientPayloadMaxLength int
	serverPayloadMaxLength int
}

type collector struct {
	// Enabled features are non-nil
	ip      *ip
	ipid    *ipid
	ttl     *ttl
	flags   *flags
	payload *payload
	ports   *ports
	seqnum  *seqnum
	sni     *sni
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
	f.clientPayloadMaxLength = cfg.ClientMaxLength
	f.serverPayloadMaxLength = cfg.ServerMaxLength

	return &f, nil
}

func (f *collectorFactory) NewCollector(net, transport gopacket.Flow, tcp *layers.TCP) Collector {
	var c collector
	for _, field := range f.fields {
		switch field {
		case FieldIP:
			c.ip = newIP(net)
		case FieldIPID:
			c.ipid = newIPID()
		case FieldTTL:
			c.ttl = newTTL()
		case FieldPorts:
			c.ports = newPorts()
		case FieldFlags:
			c.flags = newFlags()
		case FieldSeqNum:
			c.seqnum = newSeqNum()
		case FieldPayload:
			c.payload = newPayload(f.clientPayloadMaxLength, f.serverPayloadMaxLength)
		case FieldSNI:
			c.sni = newSNI()
		}
	}
	return &c
}

func (c *collector) ProcessPacket(packet gopacket.Packet, tcp *layers.TCP,
	ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection) {
	if c.ipid != nil {
		c.ipid.processPacket(packet)
	}
	if c.ttl != nil {
		c.ttl.processPacket(packet)
	}
	if c.flags != nil {
		c.flags.processPacket(tcp)
	}
	if c.ports != nil {
		c.ports.processPacket(tcp)
	}
	if c.seqnum != nil {
		c.seqnum.processPacket(tcp)
	}
	if c.sni != nil {
		c.sni.processPacket(packet)
	}
}

func (c *collector) ProcessReassembled(sg reassembly.ScatterGather,
	ac reassembly.AssemblerContext) {
	if c.payload != nil {
		c.payload.processReassembled(sg)
	}
}

func (c *collector) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		IPID    *ipid    `json:"ipid,omitempty"`
		IP      *ip      `json:"ip,omitempty"`
		TTL     *ttl     `json:"ttl,omitempty"`
		Flags   *flags   `json:"flags,omitempty"`
		Ports   *ports   `json:"ports,omitempty"`
		SeqNum  *seqnum  `json:"seqnum,omitempty"`
		Payload *payload `json:"payload,omitempty"`
		SNI     *sni     `json:"sni,omitempty"`
	}{
		IPID:    c.ipid,
		IP:      c.ip,
		TTL:     c.ttl,
		Flags:   c.flags,
		Ports:   c.ports,
		SeqNum:  c.seqnum,
		Payload: c.payload,
		SNI:     c.sni,
	})
}

func (c *collector) String() string {
	var b bytes.Buffer
	if c.ip != nil {
		b.WriteString(fmt.Sprintf("  IP: %s\n", c.ip))
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
	if c.ports != nil {
		b.WriteString(fmt.Sprintf("  Ports: %s\n", c.ports))
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
	return b.String()
}

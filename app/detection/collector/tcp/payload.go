package tcp

import (
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger/data"
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/Kkevsterrr/gopacket"
	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/reassembly"
)

// ----------- Structs ------------

// Payload : Stores the payload up to maxPayloadLength (memory efficiency)
type Payload struct {
	MaxPayloadLength int
	Direction reassembly.TCPFlowDirection
}

// PayloadStream : Reassembled content gathered from the stream.
type PayloadStream struct {
	totalLength int
	// Contains the first X bytes of the TCP payload (reassembled in order)
	contents []bytes.Buffer
}

// ----------- Payload Methods -----------

// NewPayload : Creates the config level struct
func NewPayload(maxPayloadLength int, direction string) *Payload {
	var directionFlow reassembly.TCPFlowDirection

	if direction == "server" {
		directionFlow = reassembly.TCPDirClientToServer
	} else if direction == "client" {
		directionFlow = reassembly.TCPDirServerToClient
	}

	return &Payload{MaxPayloadLength: maxPayloadLength, Direction: directionFlow}
}

// GetName : Description of this interface
func (p *Payload) GetName() string {
	return "[TCP - Payload]"
}

// RelevantNewConnection : For now, only working with TCP packets so must be true
func (p *Payload) RelevantNewConnection(net, transport gopacket.Flow) bool {
	return true
}

// GetBasicInfo : No options available - return only its name
func (p *Payload) GetBasicInfo() string {
	var direction string
	if p.Direction == reassembly.TCPDirClientToServer {
		direction = "C->S"
	} else {
		direction = "S->C"
	}

	return fmt.Sprintf("%s Max Length: %d |Direction: %s", p.GetName(), p.MaxPayloadLength, direction)
}

// NewStream : Create stream level struct to store the payload of each packet
func (p *Payload) NewStream(net, transport *gopacket.Flow, tcp *layers.TCP) interface{} {
	return NewPayloadStream()
}

// ProcessPacketPayload : Appends payload for packet to PayloadStream
func (p *Payload) ProcessPacketPayload(someInterface interface{}, sg *reassembly.ScatterGather,
									   ac *reassembly.AssemblerContext) {
	stream := someInterface.(*PayloadStream)

	stream.AppendPayload(p, sg)
}

// GetData : Returns array (each packet) of payload content as a hex string.
func (p *Payload) GetData(someInterface interface{}) *data.Array {
	stream := someInterface.(*PayloadStream)

	value := stream.GetData()

	return data.NewArray(p.GetBasicInfo(), value)
}

// --------- Payload Stream Methods ------

// NewPayloadStream : Creates stream level struct
func NewPayloadStream() *PayloadStream {
	return &PayloadStream{contents: make([]bytes.Buffer, 0)}
}

// AppendPayload : Append payload of this packet
func (p *PayloadStream) AppendPayload(config *Payload, gather *reassembly.ScatterGather) {
	dir, _, _, _ := (*gather).Info()
	length, _ := (*gather).Lengths()

	// Get payload only sent by the party interested
	if dir != config.Direction {
		return
	}

	contents := bytes.Buffer{}

	payload := (*gather).Fetch(length)
	if (length + p.totalLength) < config.MaxPayloadLength {
		// Fit everything
		contents.Write(payload)
		p.totalLength += length // Update new total length
	} else {
		// Fit as much as we can up to MaxPayloadLength
		for i := 0; i < (config.MaxPayloadLength - p.totalLength); i++ {
			contents.WriteByte(payload[i])
		}
		p.totalLength = config.MaxPayloadLength
	}

	// Append the bytes of the payload to a new item in the array
	p.contents = append(p.contents, contents)
}

// GetData : Returns an array (representing each processed packet) of hex strings
func (p *PayloadStream) GetData() []string {

	hexString := make([]string, 0)

	for i, _ := range p.contents {
		hexString = append(hexString, hex.EncodeToString(p.contents[i].Bytes()))
	}

	return hexString
}
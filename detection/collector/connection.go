package collector

import (
	"github.com/Kkevsterrr/gopacket"
	"strings"
)

// RelevantNewConnection :  Determines if the collector is relevant to this new connection.
func RelevantNewConnection(collectors []Collector,
	net gopacket.Flow, transport gopacket.Flow) []Collector {
	var applicableCollectors []Collector

	for i := 0; i < len(collectors); i++ {
		if (collectors[i]).RelevantNewConnection(net, transport) {
			applicableCollectors = append(applicableCollectors, collectors[i])
		}
	}

	return applicableCollectors
}

// RelevantNewConnection :  Determines if the collector is relevant to this new connection.
func GetBasicInfo(collectors []Collector) string {
	info := make([]string, 0)

	for i := 0; i < len(collectors); i++ {
		info = append(info, collectors[i].GetBasicInfo())
	}

	return strings.Join(info, "|")
}

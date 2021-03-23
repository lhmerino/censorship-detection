package parser

import (
	"errors"
	"os"
	"time"

	"tripwire/pkg/config"
	"tripwire/pkg/logger"

	"github.com/Kkevsterrr/gopacket"
	"github.com/Kkevsterrr/gopacket/layers"
	"github.com/Kkevsterrr/gopacket/pcap"
	"github.com/Kkevsterrr/gopacket/reassembly"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	PacketsCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tripwire_packets_count",
		Help: "Number of packets observed.",
	}, []string{"transport"})
)

// packetContext Implements https://github.com/google/gopacket/blob/master/reassembly/tcpassembly.go#L602
type packetContext struct {
	CaptureInfo gopacket.CaptureInfo
}

func (c *packetContext) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}

type parser struct {
	// Packet assembler
	assembler *reassembly.Assembler

	// Gathering of packets
	pcapFile string
	iface    string

	// Interface options
	snaplen int

	// Packet Filter
	filter string

	// Flush/Close streams every X packets
	flush int
}

func NewParser(cfg config.ParserConfig, streamFactory reassembly.StreamFactory) (*parser, error) {
	// Validate config
	if cfg.Input.PcapFile == "" && cfg.Input.Interface == "" {
		return nil, errors.New("[Config] No input source specified")
	}
	if cfg.Input.PcapFile != "" && cfg.Input.Interface != "" {
		return nil, errors.New("[Config] Please specify only a single input source")
	}
	streamPool := reassembly.NewStreamPool(streamFactory)
	return &parser{
		assembler: reassembly.NewAssembler(streamPool),
		pcapFile:  cfg.Input.PcapFile,
		iface:     cfg.Input.Interface,
		filter:    cfg.Filter.BPF,
		snaplen:   cfg.SnapLen,
		flush:     cfg.Flush,
	}, nil
}

func (p *parser) Run(signalChan chan os.Signal) error {
	var handle *pcap.Handle
	var err error

	if p.pcapFile != "" {
		logger.Info.Printf("Read from pcap: %q", p.pcapFile)
		handle, err = pcap.OpenOffline(p.pcapFile)
	} else {
		logger.Info.Printf("Starting capture on interface %q with filter %v", p.iface, p.filter)
		handle, err = pcap.OpenLive(p.iface, int32(p.snaplen), true, time.Second*10)
	}
	if err != nil {
		return err
	}
	defer handle.Close()

	// Filter packets given filter argument
	if err = handle.SetBPFFilter(p.filter); err != nil {
		return err
	}

	// Packet source setup
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	done := false
	var count int

	for !done {
		select {
		case <-signalChan:
			logger.Info.Println("SIGINT: abort")
			done = true
			break
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				logger.Info.Println("End of PCAP")
				done = true
				break
			}

			count += 1
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer == nil {
				// If TCP layer does not exist
				PacketsCount.With(prometheus.Labels{"transport": "other"}).Inc()
				continue
			}
			PacketsCount.With(prometheus.Labels{"transport": "tcp"}).Inc()

			c := packetContext{
				CaptureInfo: packet.Metadata().CaptureInfo,
			}

			p.assembler.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), packet, tcpLayer.(*layers.TCP), &c)

			// Time to flush or close connections
			if count%p.flush == 0 {
				// Time reference to use when flushing or closing connections
				ref := packet.Metadata().CaptureInfo.Timestamp
				flushed, closed := p.assembler.FlushCloseOlderThan(ref.Add(time.Minute * -2))
				logger.Debug.Printf("Forced flush: %d flushed, %d closed, %d total", flushed, closed, count)
			}
		}
	}

	closed := p.assembler.FlushAll()
	logger.Debug.Printf("Final flush: %d closed, %d total", closed, count)
	return nil
}

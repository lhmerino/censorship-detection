package config

import (
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v2"
)

type DetectorConfig struct {
	Name            string `yaml:"name"` // name used for metrics logging
	Signature       string `yaml:"signature"`
	Protocol        string `yaml:"protocol"`
	Port            uint16 `yaml:"port"`
	BPF             string `yaml:"bpf"`
	TimeThresholdMs int    `yaml:"time_thresh,omitempty"`
	PacketThreshold int    `yaml:"pkt_thresh,omitempty"`
}

type CollectorConfig struct {
	Fields                 []string `yaml:"fields"`
	TruncateIPs            bool     `yaml:"truncate_ips,omitempty"`        // Used by IP
	RelativeTimestamps     bool     `yaml:"relative_timestamps,omitempty"` // Used by Timestamp
	MaxClientPayloadLength int      `yaml:"cli_maxlen,omitempty"`          // Used by Payload
	MaxServerPayloadLength int      `yaml:"srv_maxlen,omitempty"`          // Used by Payload
}

type TCPConfig struct {
	// Support streams without SYN/SYN+ACK/ACK sequence
	AllowMissingInit bool `yaml:"allowmissinginit,omitempty"`
	MaxPacketCount   int  `yaml:"max_packets"` // Maximum number of packets to accept from each of the client and server
}

type InputConfig struct {
	Interface string `yaml:"interface,omitempty"`
	PcapFile  string `yaml:"pcap,omitempty"`
}

type ParserConfig struct {
	Input  InputConfig `yaml:"input,omitempty"`
	Filter struct {
		BPF string `yaml:"bpf,omitempty"`
	} `yaml:"filter,omitempty"`
	SnapLen int       `yaml:"snaplen,omitempty"`
	Flush   int       `yaml:"flush,omitempty"`
	TCP     TCPConfig `yaml:"tcp,omitempty"`
}

type LoggerConfig struct {
	Debug   bool   `yaml:"debug"`
	Outform string `yaml:"outform"`
}

type addrYaml struct {
	Netw string `yaml:"netw"`
	Addr string `yaml:"addr"`
}

type Config struct {
	Logger    LoggerConfig     `yaml:"logger"`
	Parser    ParserConfig     `yaml:"parser"`
	Detectors []DetectorConfig `yaml:"detectors"`
	Collector CollectorConfig  `yaml:"collector"`
	Metrics   *addrYaml        `yaml:"metrics,omitempty"`
}

func (addr addrYaml) Network() string { return addr.Netw }
func (addr addrYaml) String() string  { return addr.Addr }

func (cfg *Config) Write(w io.Writer) error {
	encoder := yaml.NewEncoder(w)
	defer encoder.Close()
	return encoder.Encode(cfg)
}

func (cfg *Config) Read(r io.Reader) error {
	decoder := yaml.NewDecoder(r)
	if err := decoder.Decode(&cfg); err != nil {
		return err
	}
	cfg.SetDefaults()
	return nil
}

// SetDefaults sets defaults for unspecified config options
func (cfg *Config) SetDefaults() {
	if cfg.Logger.Outform == "" {
		cfg.Logger.Outform = "json"
	}
	if cfg.Parser.Flush == 0 {
		cfg.Parser.Flush = 50
	}
	if cfg.Parser.TCP.MaxPacketCount == 0 {
		cfg.Parser.TCP.MaxPacketCount = 25
	}
	if len(cfg.Detectors) == 0 {
		cfg.Detectors = []DetectorConfig{
			{
				Signature: "RSTACKS",
				Protocol:  "HTTP",
				Port:      80,
			},
			{
				Signature: "RSTACKS",
				Protocol:  "HTTPS",
				Port:      443,
			},
			{
				Signature: "WIN",
				Protocol:  "HTTP",
				Port:      80,
			},
			{
				Signature: "WIN",
				Protocol:  "HTTPS",
				Port:      443,
			},
		}
	}
	if len(cfg.Collector.Fields) == 0 {
		cfg.Collector.Fields = []string{"ip", "ports", "direction",
			"timestamp", "ipid", "ttl", "flags", "seqnum", "sni",
			"host", "extensions"}
		cfg.Collector.TruncateIPs = true
	}

	var filters []string
	for idx := range cfg.Detectors {
		if cfg.Detectors[idx].Name == "" {
			cfg.Detectors[idx].Name = fmt.Sprintf("%s_%d_%s",
				strings.ToLower(cfg.Detectors[idx].Protocol),
				cfg.Detectors[idx].Port,
				strings.ToLower(cfg.Detectors[idx].Signature))
		}
		if cfg.Detectors[idx].BPF == "" {
			cfg.Detectors[idx].BPF = fmt.Sprintf("tcp and port %d", cfg.Detectors[idx].Port)
		}
		filters = append(filters, fmt.Sprintf("(%s)", cfg.Detectors[idx].BPF))
		if strings.ToLower(cfg.Detectors[idx].Signature) == "time" && cfg.Detectors[idx].TimeThresholdMs == 0 {
			cfg.Detectors[idx].TimeThresholdMs = 10
		}
		if strings.ToLower(cfg.Detectors[idx].Signature) == "packetcount" && cfg.Detectors[idx].PacketThreshold == 0 {
			cfg.Detectors[idx].PacketThreshold = 10
		}
	}

	if cfg.Parser.Filter.BPF == "" {
		cfg.Parser.Filter.BPF = strings.Join(filters, " or ")
	}
}

func DefaultConfig() *Config {
	cfg := new(Config)
	cfg.SetDefaults()
	return cfg
}

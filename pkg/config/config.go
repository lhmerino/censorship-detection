package config

import (
	"io"
	"io/ioutil"
	"log"
	"os"
	"tripwire/pkg/util/logger"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

type DetectorConfig struct {
	Name      string `yaml:"name"` // name used for metrics logging
	Heuristic string `yaml:"heuristic"`
	Protocol  string `yaml:"protocol"`
	Filter    string `yaml:"filter"`
	Port      uint16 `yaml:"port"`
}

type CollectorConfig struct {
	Fields                 []string `yaml:"fields"`
	TruncateIPs            bool     `yaml:"truncate_ips"`        // Used by IP
	RelativeTimestamps     bool     `yaml:"relative_timestamps"` // Used by Timestamp
	MaxPacketCount         int      `yaml:"max_packets"`         // Used by any collector that calls processPacket
	MaxClientPayloadLength int      `yaml:"cli_maxlen"`          // Used by Payload
	MaxServerPayloadLength int      `yaml:"srv_maxlen"`          // Used by Payload
}

type TCPConfig struct {
	// Support streams without SYN/SYN+ACK/ACK sequence
	// Not yet implemented. For an example of its use, see
	// https://github.com/google/gopacket/blob/master/examples/reassemblydump/main.go#L48
	AllowMissingInit bool `yaml:"allowmissinginit"`
}

type ParserConfig struct {
	Input struct {
		Interface string `yaml:"interface"`
		PcapFile  string `yaml:"pcap"`
	} `yaml:"input"`
	Filter struct {
		BPF string `yaml:"bpf"`
	} `yaml:"filter"`
	SnapLen int `yaml:"snaplen"`
	Flush   int `yaml:"flush"`
	// TCP-specific parser options
	TCPConfig TCPConfig `yaml:"tcp"`
}

// Config :
//	Config representation in YAML config file
type Config struct {
	Logger struct {
		Debug   bool   `yaml:"debug"`
		Outform string `yaml:"outform"`
	} `yaml:"logger"`
	Parser          ParserConfig     `yaml:"parser"`
	DetectorConfigs []DetectorConfig `yaml:"detectors"`
	CollectorConfig CollectorConfig  `yaml:"collector"`
	Metrics         *addrYaml        `yaml:"metrics"`

	StreamHandle io.Writer
}

type addrYaml struct {
	Netw string `yaml:"netw"`
	Addr string `yaml:"addr"`
}

func (addr addrYaml) Network() string { return addr.Netw }
func (addr addrYaml) String() string  { return addr.Addr }

// ReadConfig :
//	Read YAML config file
func ReadConfig(configFile string) Config {
	f, err := os.Open(configFile)
	err = errors.Wrapf(err, "reading config file %s", configFile)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	var cfg Config
	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&cfg)
	err = errors.Wrapf(err, "decoding config file %s", configFile)
	if err != nil {
		log.Fatal(err)
	}

	cfg.StreamHandle = os.Stdout

	if !cfg.Logger.Debug {
		logger.Debug.SetOutput(ioutil.Discard)
	}

	return cfg
}

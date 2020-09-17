package config

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"os"
)

// Measurement Options :
//	Definition of options for measurements
type MeasurementOptions struct {
	Direction bool `yaml:"direction"` // Used by Protocol
}

// MeasurementConfig :
//	Measurement representation in YAML config file
type MeasurementConfig struct {
	Censor   string             `yaml:"censor"`
	Protocol string             `yaml:"protocol"`
	Port     uint16             `yaml:"port"`
	Options  MeasurementOptions `yaml:"options"`
}

// Collector Options : Definition of options for data collectors
type CollectorOptions struct {
	Direction string `yaml:"direction"` // Used by Payload (client, server)
	MaxLength int    `yaml:"maxLength"` // Used by Payload
}

// CollectorConfig : Collector representation in YAML file
type CollectorConfig struct {
	Type    string           `yaml:"type"`
	Options CollectorOptions `yaml:"options"`
}

// Config :
//	Config representation in YAML config file
type Config struct {
	Logging struct {
		Level struct {
			Verbose bool `yaml:"verbose"`
			Debug   bool `yaml:"debug"`
			Info    bool `yaml:"info"`
			Quiet   bool `yaml:"quiet"`
		} `yaml:"level"`
		Output struct {
			File string `yaml:"file"`
			Fd   int    `yaml:"fd"`
		} `yaml:"output"`
		Type          string `yaml:"type"`
		PacketHexdump bool   `yaml:"packet_hexdump"`
	} `yaml:"logging"`
	Packet struct {
		Input struct {
			Interface string `yaml:"interface"`
			PcapFile  string `yaml:"pcapFile"`
		} `yaml:"input"`
		Filter struct {
			BPF string `yaml:"BPF"`
		} `yaml:"filter"`
		SnapLen int    `yaml:"snaplen"`
		Flush   uint64 `yaml:"flush"`
	} `yaml:"packet"`
	Protocol struct {
		TCP struct {
			AllowMissingInit bool `yaml:"allowmissinginit"`
		} `yaml:"tcp"`
		HTTP struct {
			Port int `yaml:"port"`
		} `yaml:"http"`
	} `yaml:"protocol"`
	MeasurementConfigs []MeasurementConfig `yaml:"measurements"`
	Collectors         struct {
		Net []CollectorConfig `yaml:"net"`
		TCP []CollectorConfig `yaml:"tcp"`
	} `yaml:"collectors"`
	Profile struct {
		CPU struct {
			Enabled bool   `yaml:"enabled"`
			File    string `yaml:"file"`
			Fd      int    `yaml:"fd"`
		} `yaml:"cpu"`
		Memory struct {
			Enabled bool   `yaml:"enabled"`
			File    string `yaml:"file"`
			Fd      int    `yaml:"fd"`
		} `yaml:"memory"`
		HTTPServer struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"httpServer"`
	} `yaml:"profile"`
	Metrics *addrYaml `yaml:"metrics,omitempty"`
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
	if err != nil {
		println("Error reading config file!")
		os.Exit(1)
	}
	defer f.Close()

	var cfg Config
	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&cfg)
	if err != nil {
		fmt.Printf("Cannot decode config file! %s\n", err.Error())
		os.Exit(2)
	}

	return cfg
}
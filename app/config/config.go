package config

import (
	"breakerspace.cs.umd.edu/censorship/measurement/detection/censor"
	"breakerspace.cs.umd.edu/censorship/measurement/detection/protocol"
	"fmt"
	"gopkg.in/yaml.v2"
	"os"
)

// MeasurementConfig :
//	Measurement representation in YAML config file
type MeasurementConfig struct {
	Censor string `yaml:"censor"`
	Protocol string `yaml:"protocol"`
	Port uint16 `yaml:"port"`
}

// Config :
//	Config representation in YAML config file
type Config struct {
	Logging struct {
		Level struct {
			Verbose bool `yaml:"verbose"`
			Debug bool `yaml:"debug"`
			Info bool `yaml:"info"`
			Quiet bool `yaml:"quiet"`
		} `yaml:"level"`
		Output struct {
			File string `yaml:"file"`
			Fd int `yaml:"fd"`
		} `yaml:"output"`
		Type string `yaml:"type"`
		PacketHexdump bool `yaml:"packet_hexdump"`
	} `yaml:"logging"`
	Packet struct {
		Input struct {
			Interface string `yaml:"interface"`
			PcapFile string `yaml:"pcapFile"`
		} `yaml:"input"`
		Filter struct {
			BPF string `yaml:"BPF"`
		} `yaml:"filter"`
		SnapLen int `yaml:"snaplen"`
		Flush uint64 `yaml:"flush"`
	} `yaml:"packet"`
	Protocol struct {
		TCP struct {
			AllowMissingInit bool `yaml:"allowmissinginit"`
		} `yaml:"tcp"`
		HTTP struct {
			Port int `yaml:"port"`
		} `yaml:"http"`
	} `yaml:"protocol"`
	MeasurementConfigs [] MeasurementConfig `yaml:"measurements"`
	Profile struct {
		CPU struct {
			Enabled bool `yaml:"enabled"`
			File string `yaml:"file"`
			Fd int `yaml:"fd"`
		} `yaml:"cpu"`
		Memory struct {
			Enabled bool `yaml:"enabled"`
			File string `yaml:"file"`
			Fd int `yaml:"fd"`
		} `yaml:"memory"`
		HTTPServer struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"httpServer"`
	} `yaml:"profile"`
}

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


// ReadProtocolFromMeasurementConfig :
//	Returns the protocol implementation given the string value
//	specified in the measurement definition in the YAML file
func ReadProtocolFromMeasurementConfig(measurement *MeasurementConfig) protocol.Protocol {
	// Protocols
	if measurement.Protocol == "HTTP" {
		return protocol.NewHTTPCustom(measurement.Port)
	}
	fmt.Println(measurement.Protocol)
	fmt.Printf("[Config2] Invalid Measurement Protocol %s\n", measurement.Protocol)
	os.Exit(1)
	return nil
}

// ReadCensorFromMeasurementConfig :
//	Returns the censor implementation given the string value
//	specified in the measurement definition in the YAML file
func ReadCensorFromMeasurementConfig(measurement *MeasurementConfig) censor.Censor {
	if measurement.Censor == "China" {
		return censor.NewChina()
	}

	fmt.Printf("[Config2] Invalid Measurement Censor %s\n", measurement.Censor)
	os.Exit(1)
	return nil
}
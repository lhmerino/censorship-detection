package config

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"os"
)

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
	Profile struct {
		CPU struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"cpu"`
		Memory struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"memory"`
	} `yaml:"profile"`
}

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
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"tripwire/pkg/collector"
	"tripwire/pkg/config"
	"tripwire/pkg/detector"
	"tripwire/pkg/logger"
	"tripwire/pkg/metrics"
	"tripwire/pkg/parser"
	"tripwire/pkg/tcpstream"

	"github.com/pkg/errors"
)

var (
	printVersion = flag.Bool("version", false, "Print version and exit.")
	dumpConfig   = flag.Bool("dump-config", false, "Print current configuration and exit.")
	configFile   = flag.String("config", "", "Config file to use. Defaults are applied for any unspecified options.")
	pcapFile     = flag.String("pcap", "", "Read packets from pcap file. Standard input is used if set to ``-''.")
	iface        = flag.String("iface", "", "Interface on which to listen.")
	bpfFilter    = flag.String("bpf", "", "BPF to filter input packets.")

	// Set at compile time with -ldflags
	version = "dev"
)

func main() {
	flag.Parse()

	if *printVersion {
		fmt.Printf("tripwire %s", version)
		return
	}

	var cfg *config.Config
	if *configFile != "" {
		cfg = readConfig(*configFile)
	} else {
		cfg = config.DefaultConfig()
	}

	// Override config with command-line arguments
	overrideArgs(cfg)

	if *dumpConfig {
		if err := cfg.Write(os.Stdout); err != nil {
			log.Fatal(err)
		}
		return
	}

	// Run Application
	run(cfg)
}

// readConfig reads a configuration from file, applying defaults for
// unspecified options
func readConfig(filename string) *config.Config {
	f, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	cfg := new(config.Config)
	if err = cfg.Read(f); err != nil {
		log.Fatal(err)
	}
	return cfg
}

func overrideArgs(cfg *config.Config) {
	if *pcapFile != "" {
		cfg.Parser.Input.PcapFile = *pcapFile
	}
	if *iface != "" {
		cfg.Parser.Input.Interface = *iface
	}
	if *bpfFilter != "" {
		cfg.Parser.Filter.BPF = *bpfFilter
	}
}

func run(cfg *config.Config) {

	// Set up stream writer
	streamWriterFunc := func([]detector.Detector, collector.Collector) {}
	switch cfg.Logger.Outform {
	case "json":
		streamWriterFunc = func(d []detector.Detector, c collector.Collector) {
			bytes, err := json.Marshal(struct {
				Version   string              `json:"version"`
				Detectors []detector.Detector `json:"detectors"`
				Collector collector.Collector `json:"collector"`
			}{
				Version:   version,
				Detectors: d,
				Collector: c,
			})
			err = errors.Wrapf(err, "Unable to marshal JSON")
			if err != nil {
				log.Fatal(err)
			} else {
				fmt.Fprintln(logger.StreamWriter, string(bytes))
			}
		}
	case "txt":
		streamWriterFunc = func(d []detector.Detector, c collector.Collector) {
			fmt.Fprintf(logger.StreamWriter, "Version: %s\nDetectors: %s\nCollectors:\n%s\n", version, d, c)
		}
	}

	// Configure debug logging
	if !cfg.Logger.Debug {
		logger.Debug.SetOutput(ioutil.Discard)
	}

	// Set up detector factories
	var dfs []detector.DetectorFactory
	for _, dc := range cfg.Detectors {
		df, err := detector.NewDetectorFactory(dc)
		if err != nil {
			log.Fatal(err)
		}
		dfs = append(dfs, df)
	}
	logger.Info.Printf("Initialized detectors")

	// Set up collector factory
	cf, err := collector.NewCollectorFactory(cfg.Collector)
	if err != nil {
		log.Fatal(err)
	}
	logger.Info.Printf("Initialized collectors")

	// Set up stream factory
	sf := tcpstream.NewTCPStreamFactory(cfg.Parser.TCP, cf, dfs, streamWriterFunc)

	// Set up parser
	p, err := parser.NewParser(cfg.Parser, sf)
	if err != nil {
		log.Fatal(err)
	}

	// Set up metrics
	server := &http.Server{}
	if cfg.Metrics != nil {
		netw, addr := cfg.Metrics.Network(), cfg.Metrics.String()
		metricsListener, err := net.Listen(netw, addr)
		err = errors.Wrapf(err, "metrics, netw=%v, addr=%v", netw, addr)
		if err != nil {
			log.Fatal(err)
		}
		logger.Info.Printf("Starting metrics server")
		go metrics.Start(server, metricsListener)
	}
	var labels []string
	for _, df := range dfs {
		labels = append(labels, df.Label())
	}

	// Print metrics upon receiving a SIGUSR1
	infoChan := make(chan os.Signal, 1)
	signal.Notify(infoChan, syscall.SIGUSR1)
	go func() {
		for {
			<-infoChan
			metrics.Print(labels)
		}
	}()

	// Run parser and clean up and exit upon receiving a SIGINT/SIGTERM
	logger.Info.Printf("Running parser")
	quitChan := make(chan os.Signal, 1)
	signal.Notify(quitChan, syscall.SIGINT, syscall.SIGTERM)
	err = p.Run(quitChan)
	if err != nil {
		log.Fatal(err)
	}

	// Print metrics
	metrics.Print(labels)

	// Clean up
	logger.Info.Printf("Stopping metrics server")
	err = server.Close()
	if err != nil {
		log.Fatal(err)
	}
}

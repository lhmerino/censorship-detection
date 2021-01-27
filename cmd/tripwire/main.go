package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"tripwire/pkg/collector"
	"tripwire/pkg/config"
	"tripwire/pkg/detector"
	"tripwire/pkg/metrics"
	"tripwire/pkg/parser"
	"tripwire/pkg/tcpstream"
	"tripwire/pkg/util/logger"

	"github.com/pkg/errors"
)

var (
	configFile = flag.String("config", "configs/config.yml", "Config file location")
	pcapFile   = flag.String("pcap", "", "PCAP file")
	iface      = flag.String("iface", "", "Interface to get packets from")
	bpfFilter  = flag.String("bpf", "", "Override BPFFilter")
)

func main() {
	// Parse arguments
	flag.Parse()

	// Config file
	cfg := config.ReadConfig(*configFile)

	// Override common arguments
	overrideArgs(&cfg)

	// Run Application
	run(cfg)
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

func run(cfg config.Config) {

	// Set up stream writer
	streamWriter := func([]detector.Detector, collector.Collector) {}
	switch cfg.Logger.Outform {
	case "json":
		streamWriter = func(d []detector.Detector, c collector.Collector) {
			bytes, err := json.Marshal(struct {
				Detectors []detector.Detector `json:"detectors"`
				Collector collector.Collector `json:"collector"`
			}{
				Detectors: d,
				Collector: c,
			})
			err = errors.Wrapf(err, "Unable to marshal JSON")
			if err != nil {
				log.Fatal(err)
			} else {
				fmt.Fprintln(cfg.StreamHandle, string(bytes))
			}
		}
	case "txt":
		streamWriter = func(d []detector.Detector, c collector.Collector) {
			fmt.Fprintf(cfg.StreamHandle, "Detectors: %s\nCollectors:\n%s\n", d, c)
		}
	}

	// Set up detector factories
	var dfs []detector.DetectorFactory
	for _, dc := range cfg.DetectorConfigs {
		df, err := detector.NewDetectorFactory(dc)
		if err != nil {
			log.Fatal(err)
		}
		dfs = append(dfs, df)
	}
	logger.Info.Printf("Initialized detectors")

	// Set up collector factory
	cf, err := collector.NewCollectorFactory(cfg.CollectorConfig)
	if err != nil {
		log.Fatal(err)
	}
	logger.Info.Printf("Initialized collectors")

	// Construct BPF Filter (if not specified in arguments) to only
	// select flows that are relevant to the detectors created
	if cfg.Parser.Filter.BPF == "" {
		var filters []string
		for _, df := range dfs {
			filters = append(filters, fmt.Sprintf("(%s)", df.BPFFilter()))
		}
		cfg.Parser.Filter.BPF = strings.Join(filters, " or ")
	}
	logger.Debug.Printf("BPF Filter: %s", cfg.Parser.Filter.BPF)

	// Set up stream factory
	sf := tcpstream.NewTCPStreamFactory(cfg.Parser.TCPConfig, cf, dfs, streamWriter)

	// Set up parser
	p := parser.NewParser(cfg.Parser, sf)

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

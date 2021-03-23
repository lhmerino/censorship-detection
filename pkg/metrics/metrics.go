package metrics

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"runtime"
	"strings"

	"tripwire/pkg/logger"
	"tripwire/pkg/parser"
	"tripwire/pkg/tcpstream"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
)

var (
	buildInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "build_info",
			Help: "A metric with a constant '1' value labeled by version, and goversion from which tripwire was built.",
		},
		[]string{"version", "goversion"},
	)
	Version   string = "dev"
	GoVersion        = runtime.Version()
)

// metrics registers metrics with Prometheus and starts the server.
func Start(server *http.Server, metricsListener net.Listener) {
	buildInfo.WithLabelValues(Version, GoVersion).Set(1)

	registry := []prometheus.Collector{
		buildInfo, parser.PacketsCount, tcpstream.StreamsCount,
	}

	for i, coll := range registry {
		err := prometheus.Register(coll)
		if err != nil {
			log.Fatalf("%v (metric %v)", err, i)
		}
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	mux.HandleFunc("/debug/version", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "Version: %s, GoVersion: %s", Version, GoVersion)
	})

	server.Handler = mux

	if err := server.Serve(metricsListener); err != nil {
		if strings.Contains(err.Error(), "closed network connection") {
			logger.Info.Println("terminating metrics listener")
		} else if strings.Contains(err.Error(), "Server closed") {
			logger.Info.Println("http prometheus server closed")
		} else {
			log.Fatal(err)
		}
	}
}

func Print(labels []string) {
	var err error
	var m = &dto.Metric{}
	var counter prometheus.Counter

	if counter, err = parser.PacketsCount.GetMetricWithLabelValues("tcp"); err != nil {
		log.Fatal(err)
	}
	if err = counter.Write(m); err != nil {
		log.Fatal(err)
	}
	tcpPackets := int(m.Counter.GetValue())

	if counter, err = parser.PacketsCount.GetMetricWithLabelValues("other"); err != nil {
		log.Fatal(err)
	}
	if err = counter.Write(m); err != nil {
		log.Fatal(err)
	}
	otherPackets := int(m.Counter.GetValue())

	logger.Info.Printf("global_packets: %d tcp, %d other", tcpPackets, otherPackets)

	labels = append([]string{"global_streams"}, labels...)
	for _, label := range labels {
		if counter, err = tcpstream.StreamsCount.GetMetricWithLabelValues(label, "false"); err != nil {
			log.Fatal(err)
		}
		if err = counter.Write(m); err != nil {
			log.Fatal(err)
		}
		streamsCount := int(m.Counter.GetValue())
		if counter, err = tcpstream.StreamsCount.GetMetricWithLabelValues(label, "true"); err != nil {
			log.Fatal(err)
		}
		if err = counter.Write(m); err != nil {
			log.Fatal(err)
		}
		disruptedStreamsCount := int(m.Counter.GetValue())
		logger.Info.Printf("%s: %d total, %d disrupted", label, streamsCount+disruptedStreamsCount, disruptedStreamsCount)
	}
}

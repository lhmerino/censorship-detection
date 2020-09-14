package metrics

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"runtime"
	"strings"

	"breakerspace.cs.umd.edu/censorship/measurement/connection"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	buildInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "build_info",
			Help: "A metric with a constant '1' value labeled by version, and goversion from which tls-1000 was built.",
		},
		[]string{"version", "goversion"},
	)
	Version   string = "dev"
	GoVersion        = runtime.Version()
)

// metrics registers metrics with Prometheus and starts the server.
func Start(metricsList net.Listener) {
	buildInfo.WithLabelValues(Version, GoVersion).Set(1)

	registry := []prometheus.Collector{
		buildInfo, connection.PacketsCount,
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

	server := http.Server{
		Handler: mux,
	}

	if err := server.Serve(metricsList); err != nil {
		if strings.Contains(err.Error(), "closed network connection") {
			log.Println("terminating metrics listener")
		} else {
			log.Fatal(err)
		}
	}
}

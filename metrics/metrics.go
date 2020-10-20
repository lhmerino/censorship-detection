package metrics

import (
	"breakerspace.cs.umd.edu/censorship/measurement/connection/tcp"
	"breakerspace.cs.umd.edu/censorship/measurement/detection"
	"breakerspace.cs.umd.edu/censorship/measurement/utils/logger"
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
func Start(server *http.Server, metricsList net.Listener) {
	buildInfo.WithLabelValues(Version, GoVersion).Set(1)

	registry := []prometheus.Collector{
		buildInfo, connection.PacketsCount, tcp.StreamsCount, tcp.DisruptedStreamsCount,
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

	if err := server.Serve(metricsList); err != nil {
		if strings.Contains(err.Error(), "closed network connection") {
			log.Println("terminating metrics listener")
		} else if strings.Contains(err.Error(), "Server closed") {
			log.Println("http prometheus server closed")
		} else {
			log.Fatal(err)
		}
	}
}

func Print() {
	var m = &dto.Metric{}
	if err := connection.PacketsCount.Write(m); err != nil {
		log.Fatal(err)
	}
	str := fmt.Sprintf("Global: Processed %v packets", m.Counter.GetValue())
	log.Println(str)
	logger.Logger.Info(str)

	if err := tcp.StreamsCount.Write(m); err != nil {
		log.Fatal(err)
	}
	str = fmt.Sprintf("Global: Processed %v streams", m.Counter.GetValue())
	log.Println(str)
	logger.Logger.Info(str)

	if err := tcp.DisruptedStreamsCount.Write(m); err != nil {
		log.Fatal(err)
	}
	str = fmt.Sprintf("Global: Processed %v disrupted streams", m.Counter.GetValue())
	log.Println(str)
	logger.Logger.Info(str)

	// Measurements
	for i := 0; i < len(detection.Measurements); i++ {
		name := (*detection.Measurements[i].Censor).GetBasicInfo() + "-" + (*detection.Measurements[i].Protocol).GetBasicInfo()

		// Total Streams
		if err := detection.Measurements[i].StreamsCount.Write(m); err != nil {
			log.Fatal(err)
		}
		str = fmt.Sprintf("%s: Processed %v streams", name, m.Counter.GetValue())
		log.Println(str)
		logger.Logger.Info(str)

		// Disrupted Streams
		if err := detection.Measurements[i].DisruptedStreamsCount.Write(m); err != nil {
			log.Fatal(err)
		}
		str = fmt.Sprintf("%s: Processed %v disrupted streams", name, m.Counter.GetValue())
		log.Println(str)
		logger.Logger.Info(str)
	}

}

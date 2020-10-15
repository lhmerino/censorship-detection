package setup

import (
	"breakerspace.cs.umd.edu/censorship/measurement/config"
	"breakerspace.cs.umd.edu/censorship/measurement/metrics"
	"log"
	"net/http"
	"os"
	"runtime"
	"runtime/pprof"
)

func EndConfiguration(cfg *config.Config, cpuFile *os.File, memFile *os.File, server *http.Server) {
	//Write CPU profile
	if cpuFile != nil {
		pprof.StopCPUProfile()
		cpuFile.Close()
	}

	// Write memory profile
	if memFile != nil {
		runtime.GC() // get up-to-date statistics
		if err := pprof.WriteHeapProfile(memFile); err != nil {
			log.Fatal("could not write memory profile: ", err)
		}
		memFile.Close()
	}

	// Print metrics
	if cfg.Metrics != nil {
		metrics.Print()
	}

	_ = server.Close()
}

package executor

import (
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/named-data/ndnd/fw/core"
)

type Profiler struct {
	config  *core.Config
	cpuFile *os.File
	block   *pprof.Profile
}

func NewProfiler(config *core.Config) *Profiler {
	return &Profiler{config: config}
}

func (p *Profiler) String() string {
	return "profiler"
}

func (p *Profiler) Start() (err error) {
	if p.config.Core.CpuProfile != "" {
		p.cpuFile, err = os.Create(p.config.Core.CpuProfile)
		if err != nil {
			core.Log.Fatal(p, "Unable to open output file for CPU profile", "err", err)
		}

		core.Log.Info(p, "Profiling CPU", "out", p.config.Core.CpuProfile)
		pprof.StartCPUProfile(p.cpuFile)
	}

	if p.config.Core.BlockProfile != "" {
		core.Log.Info(p, "Profiling blocking operations", "out", p.config.Core.BlockProfile)
		runtime.SetBlockProfileRate(1)
		p.block = pprof.Lookup("block")
	}

	return
}

func (p *Profiler) Stop() {
	if p.block != nil {
		blockProfileFile, err := os.Create(p.config.Core.BlockProfile)
		if err != nil {
			core.Log.Fatal(p, "Unable to open output file for block profile", "err", err)
		}
		if err := p.block.WriteTo(blockProfileFile, 0); err != nil {
			core.Log.Fatal(p, "Unable to write block profile", "err", err)
		}
		blockProfileFile.Close()
	}

	if p.config.Core.MemProfile != "" {
		memProfileFile, err := os.Create(p.config.Core.MemProfile)
		if err != nil {
			core.Log.Fatal(p, "Unable to open output file for memory profile", "err", err)
		}
		defer memProfileFile.Close()

		core.Log.Info(p, "Profiling memory", "out", p.config.Core.MemProfile)
		runtime.GC()
		if err := pprof.WriteHeapProfile(memProfileFile); err != nil {
			core.Log.Fatal(p, "Unable to write memory profile", "err", err)
		}
	}

	if p.cpuFile != nil {
		pprof.StopCPUProfile()
		p.cpuFile.Close()
	}
}

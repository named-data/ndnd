package rdr

import (
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/schema"
)

type RdrPipeline interface {
}

type RdrPipelineFixed struct {
	MaxPipelineSize uint64
}

type RdrPipelineAdaptive struct {
	InitCwnd         float64
	InitSsthresh     float64
	RtoCheckInterval time.Duration
	IgnoreCongMarks  bool
	DisableCwa       bool
}

type RdrPipelineAimd struct {
	RdrPipelineAdaptive

	AiStep          float64
	MdCoef          float64
	ResetCwndToInit bool
}

type RdrPipelineCubic struct {
	RdrPipelineAdaptive

	CubicBeta      float64
	EnableFastConv bool
}

// DataFetcher tries to get specified Data packet up to `maxRetries` times.
func DataFetcher(mNode schema.MatchedNode, intConfig *ndn.InterestConfig, maxRetries int) schema.NeedResult {
	var result schema.NeedResult
	for j := 0; j < maxRetries; j++ {
		log.Debug(mNode.Node, "Fetching", "j", j, "retries", maxRetries)
		result = <-mNode.Call("NeedChan").(chan schema.NeedResult)
		switch result.Status {
		case ndn.InterestResultData:
			return result
		}
	}
	return result
}

// Run executes the pipeline in a standalone goroutine with blocking setting.
func (p *RdrPipelineFixed) Run(mNode schema.MatchedNode, callback schema.Callback, manifest []enc.Buffer) {
	// lock := sync.RWMutex{}
	// fragments := make(enc.Wire, len(manifest))
	// nextFrag := uint64(0)
	// wg := sync.WaitGroup{}
	// wg.Add(int(p.MaxPipelineSize))

	// wg.Wait()
}

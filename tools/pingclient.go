package tools

import (
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"os/signal"
	"syscall"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/utils"
)

type PingClient struct {
	args   []string
	prefix enc.Name
	name   enc.Name
	app    ndn.Engine

	// command line configuration
	interval int
	timeout  int
	count    int
	seq      uint64 // changes with each ping

	// stat counters
	nRecv    int
	nNack    int
	nTimeout int

	// stat time counters
	totalTime  time.Duration
	totalCount int

	// stat rtt counters
	rttMin time.Duration
	rttMax time.Duration
	rttAvg time.Duration
}

func RunPingClient(args []string) {
	(&PingClient{args: args}).run()
}

func (pc *PingClient) String() string {
	return "ping"
}

func (pc *PingClient) usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <prefix>\n", pc.args[0])
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "Ping a NDN name prefix using Interests with name ndn:/name/prefix/ping/number.\n")
	fmt.Fprintf(os.Stderr, "The numbers in the Interests are randomly generated\n")
}

func (pc *PingClient) send(seq uint64) {
	name := pc.name.Append(enc.NewSequenceNumComponent(seq))

	cfg := &ndn.InterestConfig{
		Lifetime: utils.IdPtr(time.Duration(pc.timeout) * time.Millisecond),
		Nonce:    utils.ConvertNonce(pc.app.Timer().Nonce()),
	}

	interest, err := pc.app.Spec().MakeInterest(name, cfg, nil, nil)
	if err != nil {
		log.Error(pc, "Unable to make Interest", "err", err)
		return
	}

	pc.totalCount++
	t1 := time.Now()

	err = pc.app.Express(interest, func(args ndn.ExpressCallbackArgs) {
		t2 := time.Now()

		switch args.Result {
		case ndn.InterestResultNack:
			fmt.Printf("nack from %s: seq=%d with reason=%d\n", pc.prefix, seq, args.NackReason)
			pc.nNack++
		case ndn.InterestResultTimeout:
			fmt.Printf("timeout from %s: seq=%d\n", pc.prefix, seq)
			pc.nTimeout++
		case ndn.InterestCancelled:
			fmt.Printf("canceled from %s: seq=%d\n", pc.prefix, seq)
			pc.nNack++
		case ndn.InterestResultData:
			fmt.Printf("content from %s: seq=%d, time=%f ms\n",
				pc.prefix, seq,
				float64(t2.Sub(t1).Microseconds())/1000.0)

			if pc.nRecv == 0 { // lateinit
				pc.rttMin = time.Duration(1<<63 - 1)
			}

			pc.nRecv++
			pc.totalTime += t2.Sub(t1)
			pc.rttMin = min(pc.rttMin, t2.Sub(t1))
			pc.rttMax = max(pc.rttMax, t2.Sub(t1))
			pc.rttAvg = pc.totalTime / time.Duration(pc.nRecv)
		}
	})
	if err != nil {
		log.Error(pc, "Unable to send Interest", "err", err)
	}
}

func (pc *PingClient) stats() {
	if pc.totalCount == 0 {
		fmt.Printf("No interests transmitted\n")
		return
	}

	fmt.Printf("\n--- %s ping statistics ---\n", pc.prefix)
	fmt.Printf("%d interests transmitted, %d received, %d%% lost\n",
		pc.totalCount, pc.nRecv, (pc.nNack+pc.nTimeout)*100/pc.totalCount)
	fmt.Printf("rtt min/avg/max = %f/%f/%f ms\n",
		float64(pc.rttMin.Microseconds())/1000.0,
		float64(pc.rttAvg.Microseconds())/1000.0,
		float64(pc.rttMax.Microseconds())/1000.0)
}

func (pc *PingClient) run() {
	flagset := flag.NewFlagSet("ping", flag.ExitOnError)
	flagset.Usage = func() {
		pc.usage()
		flagset.PrintDefaults()
	}

	flagset.IntVar(&pc.interval, "i", 1000, "ping interval, in milliseconds")
	flagset.IntVar(&pc.timeout, "t", 4000, "timeout for each ping, in milliseconds")
	flagset.IntVar(&pc.count, "c", 0, "number of pings to send")
	flagset.Uint64Var(&pc.seq, "s", 0, "start sequence number")

	// get name prefix
	flagset.Parse(pc.args[1:])
	prefix := flagset.Arg(0)
	if prefix == "" {
		flagset.Usage()
		os.Exit(3)
	}

	// parse name prefix
	prefixN, err := enc.NameFromStr(prefix)
	if err != nil {
		log.Fatal(pc, "Invalid prefix", "name", pc.args[1])
		return
	}
	pc.prefix = prefixN
	pc.name = prefixN.Append(enc.NewStringComponent(enc.TypeGenericNameComponent, "ping"))

	// initialize sequence number
	if pc.seq == 0 {
		pc.seq = rand.Uint64()
	}

	// start the engine
	pc.app = engine.NewBasicEngine(engine.NewDefaultFace())
	err = pc.app.Start()
	if err != nil {
		log.Fatal(pc, "Unable to start engine", "err", err)
		return
	}
	defer pc.app.Stop()

	// quit on signal
	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, os.Interrupt, syscall.SIGTERM)

	// start main ping routine
	fmt.Printf("PING %s\n", pc.name)
	defer pc.stats()

	// initial ping
	pc.send(pc.seq)

	// send ping periodically
	ticker := time.NewTicker(time.Duration(pc.interval) * time.Millisecond)
	for {
		select {
		case <-ticker.C:
			pc.seq++
			pc.send(pc.seq)
			if pc.count > 0 && pc.totalCount >= pc.count {
				time.Sleep(time.Duration(pc.timeout) * time.Millisecond)
				return
			}
		case <-sigchan:
			return
		}
	}
}

//go:build js && wasm

package main

import (
	"fmt"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/engine/face"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/named-data/ndnd/std/utils"
)

// (AI GENERATED DESCRIPTION): Sends a fresh Interest containing a timestamp component over a WebSocket face, then waits for and logs whether the Interest is Nacked, times out, cancelled, or returns Data.
func main() {
	app := engine.NewBasicEngine(face.NewWasmWsFace("wss://suns.cs.ucla.edu/ws/", false))
	err := app.Start()
	if err != nil {
		log.Fatal(nil, "Unable to start engine", "err", err)
		return
	}
	defer app.Stop()

	name, _ := enc.NameFromStr("/ndn/edu/ucla/ping/abc")
	name = name.Append(enc.NewTimestampComponent(utils.MakeTimestamp(time.Now())))

	intCfg := &ndn.InterestConfig{
		MustBeFresh: true,
		Lifetime:    optional.Some(6 * time.Second),
		Nonce:       utils.ConvertNonce(app.Timer().Nonce()),
	}
	interest, err := app.Spec().MakeInterest(name, intCfg, nil, nil)
	if err != nil {
		log.Error(nil, "Unable to make Interest", "err", err)
		return
	}

	fmt.Printf("Sending Interest %s\n", interest.FinalName.String())
	ch := make(chan ndn.ExpressCallbackArgs, 1)
	err = app.Express(interest, func(args ndn.ExpressCallbackArgs) { ch <- args })
	if err != nil {
		log.Error(nil, "Unable to send Interest", "err", err)
		return
	}

	fmt.Printf("Wait for result ...\n")
	args := <-ch

	switch args.Result {
	case ndn.InterestResultNack:
		fmt.Printf("Nacked with reason=%d\n", args.NackReason)
	case ndn.InterestResultTimeout:
		fmt.Printf("Timeout\n")
	case ndn.InterestCancelled:
		fmt.Printf("Canceled\n")
	case ndn.InterestResultData:
		data := args.Data
		fmt.Printf("Received Data Name: %s\n", data.Name().String())
		fmt.Printf("%+v\n", data.Content().Join())
	}
}

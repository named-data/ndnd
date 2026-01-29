package main

import (
	"fmt"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/named-data/ndnd/std/utils"
)

// (AI GENERATED DESCRIPTION): Starts an NDN BasicEngine, expresses a fresh Interest for a timestamp‑appended name, and prints the result (Data payload or Nack/timeout/cancellation) received from the network.
func main() {
	app := engine.NewBasicEngine(engine.NewDefaultFace())
	err := app.Start()
	if err != nil {
		log.Fatal(nil, "Unable to start engine", "err", err)
		return
	}
	defer app.Stop()

	name, _ := enc.NameFromStr("/example/testApp/randomData")
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
	ch := make(chan struct{})
	err = app.Express(interest,
		func(args ndn.ExpressCallbackArgs) {
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
			ch <- struct{}{}
		})
	if err != nil {
		log.Error(nil, "Unable to send Interest", "err", err)
		return
	}

	fmt.Printf("Wait for result ...\n")
	<-ch
}

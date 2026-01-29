package main

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/schema"
	"github.com/named-data/ndnd/std/schema/svs"
)

const HmacKey = "Hello, World!"

const SchemaJson = `{
  "nodes": {
    "/sync": {
      "type": "SvsNode",
      "attrs": {
        "ChannelSize": 1000,
        "SyncInterval": 2000,
        "SuppressionInterval": 100,
        "SelfName": "$nodeId",
        "BaseMatching": {}
      }
    }
  },
  "policies": [
    {
      "type": "RegisterPolicy",
      "path": "/sync/32=notif",
      "attrs": {}
    },
    {
      "type": "RegisterPolicy",
      "path": "/sync/<8=nodeId>",
      "attrs": {
        "Patterns": {
          "nodeId": "$nodeId"
        }
      }
    },
    {
      "type": "FixedHmacSigner",
      "path": "/sync/<8=nodeId>/<seq=seqNo>",
      "attrs": {
        "KeyValue": "$hmacKey"
      }
    },
    {
      "type": "FixedHmacIntSigner",
      "path": "/sync/32=notif",
      "attrs": {
        "KeyValue": "$hmacKey"
      }
    },
    {
      "type": "MemStorage",
      "path": "/sync",
      "attrs": {}
    }
  ]
}`

// (AI GENERATED DESCRIPTION): Initializes an NDN engine, attaches a sync schema, periodically publishes new data packets, and listens for missing data requests to fetch and display them.
func main() {
	// Note: remember to ` nfdc strategy set /example/schema /localhost/nfd/strategy/multicast `
	nodeId := fmt.Sprintf("node-%d", rand.Int())

	// Setup schema tree
	tree := schema.CreateFromJson(SchemaJson, map[string]any{
		"$hmacKey": HmacKey,
		"$nodeId":  nodeId,
	})

	// Start engine
	app := engine.NewBasicEngine(engine.NewDefaultFace())
	err := app.Start()
	if err != nil {
		log.Fatal(nil, "Unable to start engine", "err", err)
		return
	}
	defer app.Stop()

	// Attach schema
	prefix, _ := enc.NameFromStr("/example/schema/syncApp")
	err = tree.Attach(prefix, app)
	if err != nil {
		log.Fatal(nil, "Unable to attach the schema to the engine", "err", err)
		return
	}
	defer tree.Detach()

	path, _ := enc.NamePatternFromStr("/sync")
	node := tree.At(path)
	mNode := node.Apply(enc.Matching{})

	ctx, cancel := context.WithCancel(context.Background())
	wg := sync.WaitGroup{}
	wg.Add(2)
	// 1. Randomly produce data
	ticker := time.Tick(5 * time.Second)
	go func() {
		defer wg.Done()
		for val := 0; true; val++ {
			select {
			case <-ticker:
				text := fmt.Sprintf("[%s: TICK %d]\n", nodeId, val)
				mNode.Call("NewData", enc.Wire{[]byte(text)})
				fmt.Printf("Produced: %s", text)
			case <-ctx.Done():
				return
			}
		}
	}()

	// 2. On data received, print
	go func() {
		defer wg.Done()
		ch := mNode.Call("MissingDataChannel").(chan svs.MissingData)
		for {
			select {
			case missData := <-ch:
				for i := missData.StartSeq; i < missData.EndSeq; i++ {
					dataName := mNode.Call("GetDataName", missData.Name, i).(enc.Name)
					mLeafNode := tree.Match(dataName)
					result := <-mLeafNode.Call("NeedChan").(chan schema.NeedResult)
					if result.Status != ndn.InterestResultData {
						fmt.Printf("Data fetching failed for (%s, %d): %+v\n", missData.Name.String(), i, result.Status)
					} else {
						fmt.Printf("Fetched (%s, %d): %s", missData.Name.String(), i, string(result.Content.Join()))
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for keyboard quit signal
	sigChannel := make(chan os.Signal, 1)
	fmt.Print("Start serving ...\n")
	signal.Notify(sigChannel, os.Interrupt, syscall.SIGTERM)
	receivedSig := <-sigChannel
	log.Info(nil, "Received signal - exiting", "signal", receivedSig)
	cancel()
	wg.Wait()
}

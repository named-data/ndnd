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
        "SelfNodeId": "$nodeId",
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

func main() {
	// Note: remember to ` nfdc strategy set /example/schema /localhost/nfd/strategy/multicast `
	log.SetLevel(log.ErrorLevel)
	logger := log.WithField("module", "main")
	rand.Seed(time.Now().UnixMicro())
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
		logger.Fatalf("Unable to start engine: %+v", err)
		return
	}
	defer app.Stop()

	// Attach schema
	prefix, _ := enc.NameFromStr("/example/schema/syncApp")
	err = tree.Attach(prefix, app)
	if err != nil {
		logger.Fatalf("Unable to attach the schema to the engine: %+v", err)
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
					dataName := mNode.Call("GetDataName", missData.NodeId, i).(enc.Name)
					mLeafNode := tree.Match(dataName)
					result := <-mLeafNode.Call("NeedChan").(chan schema.NeedResult)
					if result.Status != ndn.InterestResultData {
						fmt.Printf("Data fetching failed for (%s, %d): %+v\n", missData.NodeId.String(), i, result.Status)
					} else {
						fmt.Printf("Fetched (%s, %d): %s", missData.NodeId.String(), i, string(result.Content.Join()))
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
	logger.Infof("Received signal %+v - exiting\n", receivedSig)
	cancel()
	wg.Wait()
}

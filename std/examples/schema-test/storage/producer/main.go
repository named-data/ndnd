package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/schema"
	"github.com/named-data/ndnd/std/utils"
)

const SchemaJson = `{
  "nodes": {
    "/randomData/<v=time>": {
      "type": "LeafNode",
      "attrs": {
        "CanBePrefix": false,
        "MustBeFresh": true,
        "Lifetime": 6000,
        "Freshness": 1000,
        "ValidDuration": 3153600000000.0
      }
    }
  },
  "policies": [
    {
      "type": "RegisterPolicy",
      "path": "/",
      "attrs": {
        "RegisterIf": "$isProducer"
      }
    },
    {
      "type": "Sha256Signer",
      "path": "/randomData/<v=time>",
      "attrs": {}
    },
    {
      "type": "MemStorage",
      "path": "/",
      "attrs": {}
    }
  ]
}`

// (AI GENERATED DESCRIPTION): Initializes an NDN engine, attaches a schema tree, publishes a Data packet named “/randomData/<v=time>” with the current timestamp, and waits for a termination signal.
func main() {
	// Setup schema tree
	tree := schema.CreateFromJson(SchemaJson, map[string]any{
		"$isProducer": true,
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
	prefix, _ := enc.NameFromStr("/example/schema/storageApp")
	err = tree.Attach(prefix, app)
	if err != nil {
		log.Fatal(nil, "Unable to attach the schema to the engine", "err", err)
		return
	}
	defer tree.Detach()

	// Produce data
	ver := utils.MakeTimestamp(time.Now())
	path, _ := enc.NamePatternFromStr("/randomData/<v=time>")
	node := tree.At(path)
	mNode := node.Apply(enc.Matching{
		"time": enc.Nat(ver).Bytes(),
	})
	mNode.Call("Provide", enc.Wire{[]byte("Hello, world!")})
	fmt.Printf("Generated packet with version= %d\n", ver)

	// Wait for keyboard quit signal
	sigChannel := make(chan os.Signal, 1)
	fmt.Print("Start serving ...\n")
	signal.Notify(sigChannel, os.Interrupt, syscall.SIGTERM)
	receivedSig := <-sigChannel
	log.Info(nil, "Received signal - exiting", "signal", receivedSig)
}

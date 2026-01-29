package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/schema"
)

const SchemaJson = `{
  "nodes": {
    "/randomData/<v=time>": {
      "type": "LeafNode",
      "attrs": {
        "CanBePrefix": false,
        "MustBeFresh": true,
        "Lifetime": 6000
      },
      "events": {
        "OnInterest": ["$onInterest"]
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
    }
  ]
}`

// (AI GENERATED DESCRIPTION): Handles an incoming Interest by extracting the timestamp, generating a Data packet with the content “Hello, world!”, replying to the event, and logging the response.
func onInterest(event *schema.Event) any {
	mNode := event.Target
	timestamp, _, _ := enc.ParseNat(mNode.Matching["time"])
	fmt.Printf(">> I: timestamp: %d\n", timestamp)
	content := []byte("Hello, world!")
	dataWire := mNode.Call("Provide", enc.Wire{content}).(enc.Wire)
	err := event.Reply(dataWire)
	if err != nil {
		log.Error(nil, "Unable to reply with Data", "err", err)
		return true
	}
	fmt.Printf("<< D: %s\n", mNode.Name.String())
	fmt.Printf("Content: (size: %d)\n", len(content))
	fmt.Printf("\n")
	return nil
}

// (AI GENERATED DESCRIPTION): Initializes a Named‑Data Networking application by creating a schema tree, starting the engine, attaching the schema to a name prefix, and waiting for a termination signal before shutting down.
func main() {
	// Setup schema tree
	tree := schema.CreateFromJson(SchemaJson, map[string]any{
		"$onInterest": onInterest,
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
	prefix, _ := enc.NameFromStr("/example/testApp")
	err = tree.Attach(prefix, app)
	if err != nil {
		log.Fatal(nil, "Unable to attach the schema to the engine", "err", err)
		return
	}
	defer tree.Detach()

	fmt.Print("Start serving ...\n")
	sigChannel := make(chan os.Signal, 1)
	signal.Notify(sigChannel, os.Interrupt, syscall.SIGTERM)
	receivedSig := <-sigChannel
	log.Info(nil, "Received signal - exiting\n", "signal", receivedSig)
}

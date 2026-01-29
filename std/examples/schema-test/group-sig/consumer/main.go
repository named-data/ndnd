package main

import (
	"fmt"
	"os"
	"strconv"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/schema"
	_ "github.com/named-data/ndnd/std/schema/rdr"
)

const SchemaJson = `{
  "nodes": {
    "/<v=time>": {
      "type": "GeneralObjNode",
      "attrs": {
        "MetaFreshness": 10,
        "MaxRetriesForMeta": 2,
        "ManifestFreshness": 10,
        "MaxRetriesForManifest": 2,
        "MetaLifetime": 6000,
        "Lifetime": 6000,
        "Freshness": 3153600000000,
        "ValidDuration": 3153600000000,
        "SegmentSize": 80,
        "MaxRetriesOnFailure": 3,
        "Pipeline": "SinglePacket"
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
      "path": "/<v=time>/32=data/<seg=segmentNumber>"
    },
    {
      "type": "FixedHmacSigner",
      "path": "/<v=time>/32=manifest",
      "attrs": {
        "KeyValue": "$hmacKey"
      }
    },
    {
      "type": "FixedHmacSigner",
      "path": "/<v=time>/32=metadata",
      "attrs": {
        "KeyValue": "$hmacKey"
      }
    },
    {
      "type": "MemStorage",
      "path": "/",
      "attrs": {}
    }
  ]
}`

const HmacKey = "Hello, World!"

// (AI GENERATED DESCRIPTION): Starts an NDN consumer, attaches a predefined schema, sends an Interest for the specified version number, and prints the received Data or error status.
func main() {
	if len(os.Args) < 2 {
		log.Fatal(nil, "Insufficient argument. Please input the version number given by the producer.")
		return
	}
	ver, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatal(nil, "Invalid argument")
		return
	}

	// Setup schema tree
	tree := schema.CreateFromJson(SchemaJson, map[string]any{
		"$isProducer": false,
		"$hmacKey":    HmacKey,
	})

	// Start engine
	app := engine.NewBasicEngine(engine.NewDefaultFace())
	err = app.Start()
	if err != nil {
		log.Fatal(nil, "Unable to start engine", "err", err)
		return
	}
	defer app.Stop()

	// Attach schema
	prefix, _ := enc.NameFromStr("/example/schema/groupSigApp")
	err = tree.Attach(prefix, app)
	if err != nil {
		log.Fatal(nil, "Unable to attach the schema to the engine", "err", err)
		return
	}
	defer tree.Detach()

	// Fetch the data
	path, _ := enc.NamePatternFromStr("/<v=time>")
	node := tree.At(path)
	mNode := node.Apply(enc.Matching{
		"time": enc.Nat(ver).Bytes(),
	})
	result := <-mNode.Call("NeedChan").(chan schema.NeedResult)
	switch result.Status {
	case ndn.InterestResultNone:
		fmt.Printf("Fetching failed. Please see log for detailed reason.\n")
	case ndn.InterestResultNack:
		fmt.Printf("Nacked with reason=%d\n", *result.NackReason)
	case ndn.InterestResultTimeout:
		fmt.Printf("Timeout\n")
	case ndn.InterestCancelled:
		fmt.Printf("Canceled\n")
	case ndn.InterestResultData:
		fmt.Printf("Received Data: \n")
		fmt.Printf("%s", string(result.Content.Join()))
	}
}

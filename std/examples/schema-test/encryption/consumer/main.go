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
	_ "github.com/named-data/ndnd/std/schema/demosec"
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
    },
    "/contentKey": {
      "type": "ContentKeyNode",
      "attrs": {
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
      "type": "FixedHmacSigner",
      "path": "/contentKey/<contentKeyID>",
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

// (AI GENERATED DESCRIPTION): Starts an NDN engine, queries the network for a specified version of `/randomData`, decrypts the returned Data packet with the `/contentKey`, and prints the plaintext.
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
	prefix, _ := enc.NameFromStr("/example/schema/encryptionApp")
	err = tree.Attach(prefix, app)
	if err != nil {
		log.Fatal(nil, "Unable to attach the schema to the engine", "err", err)
		return
	}
	defer tree.Detach()

	// Fetch the data
	path, _ := enc.NamePatternFromStr("/randomData/<v=time>")
	node := tree.At(path)
	mNode := node.Apply(enc.Matching{
		"time": enc.Nat(ver).Bytes(),
	})
	result := <-mNode.Call("NeedChan").(chan schema.NeedResult)
	switch result.Status {
	case ndn.InterestResultNack:
		fmt.Printf("Nacked with reason=%d\n", *result.NackReason)
	case ndn.InterestResultTimeout:
		fmt.Printf("Timeout\n")
	case ndn.InterestCancelled:
		fmt.Printf("Canceled\n")
	case ndn.InterestResultData:
		fmt.Printf("Data received\n")
	}
	if result.Status != ndn.InterestResultData {
		return
	}

	path, _ = enc.NamePatternFromStr("/contentKey")
	ckMNode := tree.At(path).Apply(enc.Matching{})
	plainText, ok := ckMNode.Call("Decrypt", result.Content).(enc.Wire)
	if !ok || plainText == nil {
		fmt.Printf("Unable to decrypt data\n")
	} else {
		fmt.Printf("Data: %s\n", string(plainText.Join()))
	}
}

package main

import (
	"encoding/base64"
	"fmt"
	"os"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/schema"
	"github.com/named-data/ndnd/std/schema/demosec"
)

const (
	TrustAnchorPktB64 = ("BsMHKAgHZXhhbXBsZQgGc2NoZW1hCAhzaWduZWRCeQgLdHJ1c3RBbmNob3IUCRgBAhkEADbugBUP" +
		"SG1hY1RydXN0QW5jaG9yFlkbAQQcKgcoCAdleGFtcGxlCAZzY2hlbWEICHNpZ25lZEJ5CAt0cnVz" +
		"dEFuY2hvcv0A/Sb9AP4PMjAyMzAyMTNUMDU1NzU0/QD/DzIwNDMwMjA4VDA1NTc1NBcg0FmaCWVb" +
		"U7ei6w5fTNGS5KOklhhMfA9eLvRaUCfYpLw=")

	SchemaJson = `{
		"nodes": {
			"/<nodeId>/data": {
				"type": "LeafNode",
				"attrs": {
					"CanBePrefix": false,
					"MustBeFresh": true,
					"Lifetime": 6000,
					"Freshness": 1000,
					"ValidDuration": 3153600000000.0
				}
			},
			"/<nodeId>/key": {
				"type": "LeafNode",
				"attrs": {
					"CanBePrefix": false,
					"MustBeFresh": true,
					"Lifetime": 6000,
					"Freshness": 3600000
				}
			},
			"/trustAnchor": {
				"type": "LeafNode",
				"attrs": {
					"CanBePrefix": false,
					"MustBeFresh": false,
					"SupressInt": true
				}
			}
		},
		"policies": [
			{
				"type": "RegisterPolicy",
				"path": "/<nodeId>",
				"attrs": {
					"RegisterIf": "$isProducer",
					"Patterns": {
						"nodeId": "$nodeId"
					}
				}
			},
			{
				"type": "SignedBy",
				"path": "/<nodeId>/data",
				"attrs": {
					"KeyNodePath": "/<nodeId>/key",
					"Mapping": {
						"nodeId": "$nodeId"
					},
					"KeyStore": "$keyStore"
				}
			},
			{
				"type": "SignedBy",
				"path": "/<nodeId>/key",
				"attrs": {
					"KeyNodePath": "/trustAnchor",
					"Mapping": {
						"nodeId": "$nodeId"
					},
					"KeyStore": "$keyStore"
				}
			},
			{
				"type": "MemStorage",
				"path": "/<nodeId>/data",
				"attrs": {}
			},
			{
				"type": "KeyStoragePolicy",
				"path": "/<nodeId>/key",
				"attrs": {
					"KeyStore": "$keyStore"
				}
			},
			{
				"type": "KeyStoragePolicy",
				"path": "/trustAnchor",
				"attrs": {
					"KeyStore": "$keyStore"
				}
			}
		]
	}`
)

// (AI GENERATED DESCRIPTION): Runs an NDN consumer that enrolls a trust anchor, attaches a schema tree, requests the Data packet named `/\<nodeId\>/data` for the given node ID, and prints the outcome (data, NACK, timeout, or cancellation).
func main() {
	if len(os.Args) < 2 {
		log.Fatal(nil, "Insufficient argument. Please input the version number given by the producer.")
		return
	}
	nodeId := os.Args[1]
	prefix, _ := enc.NameFromStr("/example/schema/signedBy")

	// Create key store
	keyStore := demosec.NewDemoHmacKeyStore()

	// Enroll trust anchor
	trustAnchorBuf, err := base64.StdEncoding.DecodeString(TrustAnchorPktB64)
	if err != nil {
		log.Fatal(nil, "Invalid trust anchor", "err", err)
		return
	}
	err = keyStore.AddTrustAnchor(trustAnchorBuf)
	if err != nil {
		log.Fatal(nil, "Unable to add trust anchor", "err", err)
		return
	}

	// Setup schema tree
	tree := schema.CreateFromJson(SchemaJson, map[string]any{
		"$isProducer": false,
		"$nodeId":     nodeId,
		"$keyStore":   keyStore,
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
	err = tree.Attach(prefix, app)
	if err != nil {
		log.Fatal(nil, "Unable to attach the schema to the engine", "err", err)
		return
	}
	defer tree.Detach()

	// Fetch the data
	path, _ := enc.NamePatternFromStr("/<nodeId>/data")
	node := tree.At(path)
	mNode := node.Apply(enc.Matching{
		"nodeId": []byte(nodeId),
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
		fmt.Printf("Received Data: %+v\n", string(result.Content.Join()))
	}
}

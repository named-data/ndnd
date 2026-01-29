package main

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"syscall"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/schema"
	"github.com/named-data/ndnd/std/schema/demosec"
)

const (
	TrustAnchorPktB64 = ("BsMHKAgHZXhhbXBsZQgGc2NoZW1hCAhzaWduZWRCeQgLdHJ1c3RBbmNob3IUCRgBAhkEADbugBUP" +
		"SG1hY1RydXN0QW5jaG9yFlkbAQQcKgcoCAdleGFtcGxlCAZzY2hlbWEICHNpZ25lZEJ5CAt0cnVz" +
		"dEFuY2hvcv0A/Sb9AP4PMjAyMzAyMTNUMDU1NzU0/QD/DzIwNDMwMjA4VDA1NTc1NBcg0FmaCWVb" +
		"U7ei6w5fTNGS5KOklhhMfA9eLvRaUCfYpLw=")
	ProducerKey = "ProducerHmacKey"

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

// (AI GENERATED DESCRIPTION): Starts a demo NDN node that enrolls a trust anchor, issues a producer key, attaches a schema, produces a “Hello, world!” data packet, and serves until interrupted.
func main() {
	nodeId := fmt.Sprintf("node-%d", rand.Int())
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
	spec := spec_2022.Spec{}
	trustAnchorData, _, _ := spec.ReadData(enc.NewBufferView(trustAnchorBuf))

	// Issue producer key (signed by the trust anchor)
	producerKeyName := enc.Name{
		prefix[0], prefix[1], prefix[2],
		enc.NewGenericComponent(nodeId),
		enc.NewGenericComponent("key"),
	}
	err = keyStore.EnrollKey(producerKeyName, enc.Buffer(ProducerKey), trustAnchorData.Name())
	if err != nil {
		log.Fatal(nil, "Unable to enroll the producer key", "err", err)
		return
	}

	// Setup schema tree
	tree := schema.CreateFromJson(SchemaJson, map[string]any{
		"$isProducer": true,
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

	// Produce data
	path, _ := enc.NamePatternFromStr("/<nodeId>/data")
	node := tree.At(path)
	mNode := node.Apply(enc.Matching{
		"nodeId": []byte(nodeId),
	})
	mNode.Call("Provide", enc.Wire{[]byte("Hello, world!")})
	fmt.Printf("Generated packet with nodeId= %s\n", nodeId)

	// Wait for keyboard quit signal
	sigChannel := make(chan os.Signal, 1)
	fmt.Print("Start serving ...\n")
	signal.Notify(sigChannel, os.Interrupt, syscall.SIGTERM)
	receivedSig := <-sigChannel
	log.Info(nil, "Received signal - exiting", "signal", receivedSig)
}

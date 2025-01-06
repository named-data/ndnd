// This example uses the old schema implemementation and does not work
package main

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/schema"
	"github.com/named-data/ndnd/std/schema/svs"
)

var homeHtmlTmp []byte
var homeHtml string
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

const HmacKey = "Hello, World!"
const SchemaJson = `{
  "nodes": {
    "/chat": {
      "type": "SvsNode",
      "attrs": {
        "ChannelSize": 1000,
        "SyncInterval": 15000,
        "SuppressionInterval": 100,
        "SelfNodeId": "$nodeId",
        "BaseMatching": {}
      }
    }
  },
  "policies": [
    {
      "type": "RegisterPolicy",
      "path": "/chat/32=notif",
      "attrs": {}
    },
    {
      "type": "RegisterPolicy",
      "path": "/chat/<8=nodeId>",
      "attrs": {
        "Patterns": {
          "nodeId": "$nodeId"
        }
      }
    },
    {
      "type": "FixedHmacSigner",
      "path": "/chat/<8=nodeId>/<seq=seqNo>",
      "attrs": {
        "KeyValue": "$hmacKey"
      }
    },
    {
      "type": "FixedHmacIntSigner",
      "path": "/chat/32=notif",
      "attrs": {
        "KeyValue": "$hmacKey"
      }
    },
    {
      "type": "MemStorage",
      "path": "/chat",
      "attrs": {}
    }
  ]
}`

var syncNode *schema.MatchedNode
var wsConn *websocket.Conn // 1 ws connection supported
var msgList []string
var dataLock sync.Mutex
var nodeId string

func homePage(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(homeHtml))
}

func wsReader() {
	running := true
	for running {
		// read in a message
		messageType, p, err := wsConn.ReadMessage()
		if err != nil {
			dataLock.Lock()
			wsConn = nil
			dataLock.Unlock()
			running = false
			continue
		}
		// print out that message
		dataLock.Lock()
		syncNode.Call("NewData", enc.Wire{p})
		mySeq := syncNode.Call("MySequence").(uint64)
		msgText := fmt.Sprintf("%s[%d]: %s", string(nodeId), mySeq, p)
		fmt.Printf("received: %s\n", msgText)
		if err := wsConn.WriteMessage(messageType, []byte(msgText)); err != nil {
			wsConn = nil
			running = false
		}
		dataLock.Unlock()
	}
}

func wsEndpoint(w http.ResponseWriter, r *http.Request) {
	upgrader.CheckOrigin = func(r *http.Request) bool { return true }

	// upgrade this connection to a WebSocket
	// connection
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println(err)
	}
	// helpful log statement to show connections
	fmt.Println("Client Connected")
	if err != nil {
		fmt.Println(err)
	}

	if wsConn == nil {
		wsConn = ws
	} else {
		ws.Close()
	}
	// Give existing knowledges
	dataLock.Lock()
	for _, msg := range msgList {
		wsConn.WriteMessage(websocket.TextMessage, []byte(msg))
	}
	dataLock.Unlock()
	// Fetch messages sent by the client
	wsReader()
}

func setupRoutes() {
	http.HandleFunc("/", homePage)
	http.HandleFunc("/ws", wsEndpoint)
}

func main() {
	// Note: remember to ` nfdc strategy set /example/schema /localhost/nfd/strategy/multicast `
	log.SetLevel(log.ErrorLevel)
	logger := log.WithField("module", "main")
	rand.Seed(time.Now().UnixMicro())

	// Parse port number
	if len(os.Args) < 2 {
		logger.Fatal("Insufficient argument. Please input a port number uniquely used by this instance.")
		return
	}
	port, err := strconv.Atoi(os.Args[1])
	if err != nil {
		logger.Fatal("Invalid argument")
		return
	}
	nodeId = fmt.Sprintf("node-%d", port)

	// Load HTML UI file to serve
	file, err := os.Open("home.html")
	if err != nil {
		logger.Fatalf("Failed to open home.html: %+v", err)
	}
	homeHtmlTmp, err = io.ReadAll(file)
	if err != nil {
		logger.Fatalf("Failed to read home.html: %+v", err)
	}
	file.Close()
	temp, err := template.New("HTML").Parse(string(homeHtmlTmp))
	if err != nil {
		logger.Fatalf("Failed to create template: %+v", err)
	}
	strBuilder := strings.Builder{}
	temp.Execute(&strBuilder, port)
	homeHtml = strBuilder.String()

	// Setup schema tree (supposed to be shared knowledge of all nodes)
	tree := schema.CreateFromJson(SchemaJson, map[string]any{
		"$hmacKey": HmacKey,
		"$nodeId":  nodeId,
	})

	// Start engine
	app := engine.NewBasicEngine(engine.NewDefaultFace())
	err = app.Start()
	if err != nil {
		logger.Fatalf("Unable to start engine: %+v", err)
		return
	}
	defer app.Stop()

	// Attach schema
	prefix, _ := enc.NameFromStr("/example/schema/chatApp")
	err = tree.Attach(prefix, app)
	if err != nil {
		logger.Fatalf("Unable to attach the schema to the engine: %+v", err)
		return
	}
	defer tree.Detach()
	path, _ := enc.NamePatternFromStr("/chat")
	syncNode = tree.At(path).Apply(enc.Matching{})

	// Start serving HTTP routes
	setupRoutes()
	server := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: nil}

	ctx, cancel := context.WithCancel(context.Background())
	wg := sync.WaitGroup{}
	wg.Add(2)
	// Routine 1: HTTP and WS server
	go func() {
		defer wg.Done()
		server.ListenAndServe()
	}()

	// Routine 2: On data received, send over ws
	msgList = make([]string, 0)
	go func() {
		defer wg.Done()
		ch := syncNode.Call("MissingDataChannel").(chan svs.MissingData)
		for {
			select {
			case missData := <-ch:
				for i := missData.StartSeq; i < missData.EndSeq; i++ {
					dataName := syncNode.Call("GetDataName", missData.NodeId, i).(enc.Name)
					mLeafNode := tree.Match(dataName)
					result := <-mLeafNode.Call("NeedChan").(chan schema.NeedResult)
					if result.Status != ndn.InterestResultData {
						fmt.Printf("Data fetching failed for (%s, %d): %+v\n", missData.NodeId.String(), i, result.Status)
					} else {
						dataLock.Lock()
						fmt.Printf("Fetched (%s, %d): %s\n", missData.NodeId.String(), i, string(result.Content.Join()))
						msg := fmt.Sprintf("%s[%d]: %s", missData.NodeId.String(), i, string(result.Content.Join()))
						msgList = append(msgList, msg)
						if wsConn != nil {
							wsConn.WriteMessage(websocket.TextMessage, []byte(msg))
						}
						dataLock.Unlock()
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for keyboard quit signal
	sigChannel := make(chan os.Signal, 1)
	fmt.Printf("Start serving on   http://localhost:%d/   ...\n", port)
	signal.Notify(sigChannel, os.Interrupt, syscall.SIGTERM)
	receivedSig := <-sigChannel
	logger.Infof("Received signal %+v - exiting\n", receivedSig)
	cancel()
	server.Shutdown(context.Background())
	wg.Wait()
}

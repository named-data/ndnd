package object

import (
	"errors"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
)

type Client struct {
	// underlying API engine
	engine ndn.Engine
	// data storage
	store ndn.Store
	// segment fetcher
	fetcher rrSegFetcher

	// stop the client
	stop chan bool
	// outgoing interest pipeline
	outpipe chan ExpressRArgs
	// [fetcher] incoming data pipeline
	seginpipe chan rrSegHandleDataArgs
	// [fetcher] queue for new object fetch
	segfetch chan *ConsumeState
	// [fetcher] recheck segment fetcher
	segcheck chan bool
}

// Create a new client with given engine and store
func NewClient(engine ndn.Engine, store ndn.Store) *Client {
	client := new(Client)
	client.engine = engine
	client.store = store
	client.fetcher = newRrSegFetcher(client)

	client.stop = make(chan bool)
	client.outpipe = make(chan ExpressRArgs, 1024)
	client.seginpipe = make(chan rrSegHandleDataArgs, 1024)
	client.segfetch = make(chan *ConsumeState, 128)
	client.segcheck = make(chan bool, 2)

	return client
}

// Instance log identifier
func (c *Client) String() string {
	return "client"
}

// Start the client. The engine must be running.
func (c *Client) Start() error {
	if !c.engine.IsRunning() {
		return errors.New("client start when engine not running")
	}

	if err := c.engine.AttachHandler(enc.Name{}, c.onInterest); err != nil {
		return err
	}

	go c.run()
	return nil
}

// Stop the client
func (c *Client) Stop() {
	c.stop <- true
}

// Get the underlying engine
func (c *Client) Engine() ndn.Engine {
	return c.engine
}

// Get the underlying store
func (c *Client) Store() ndn.Store {
	return c.store
}

// Main goroutine for all client processing
func (c *Client) run() {
	for {
		select {
		case <-c.stop:
			return
		case args := <-c.outpipe:
			c.expressRImpl(args)
		case args := <-c.seginpipe:
			c.fetcher.handleData(args.args, args.state)
		case state := <-c.segfetch:
			c.fetcher.add(state)
		case <-c.segcheck:
			c.fetcher.doCheck()
		}
	}
}

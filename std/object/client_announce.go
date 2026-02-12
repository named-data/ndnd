package object

import (
	"sync"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/named-data/ndnd/std/types/optional"
)

var announceMutex sync.Mutex

// (AI GENERATED DESCRIPTION): AnnouncePrefix registers the supplied prefix announcement in the client’s internal map and, if the NDN face is running, launches a goroutine to transmit the announcement to peers.
func (c *Client) AnnouncePrefix(args ndn.Announcement) {
	hash := args.Name.TlvStr()
	c.announcements.Store(hash, args)

	if c.engine.Face().IsRunning() {
		go c.announcePrefix_(args)
	}
}

// (AI GENERATED DESCRIPTION): Deletes the client’s stored announcement for the specified prefix name and, if the network engine’s face is running, asynchronously initiates its withdrawal.
func (c *Client) WithdrawPrefix(name enc.Name, onError func(error)) {
	hash := name.TlvStr()
	ann, ok := c.announcements.LoadAndDelete(hash)
	if !ok {
		return
	}

	if c.engine.Face().IsRunning() {
		go c.withdrawPrefix_(ann.(ndn.Announcement), onError)
	}
}

// (AI GENERATED DESCRIPTION): Announces a prefix to the network by registering it with the PIB (add‑nexthop), optionally setting its cost, and spacing the request with a short delay to accommodate NFD behavior.
func (c *Client) announcePrefix_(args ndn.Announcement) {
	announceMutex.Lock()
	time.Sleep(1 * time.Millisecond) // thanks NFD
	announceMutex.Unlock()

	_, err := c.engine.ExecMgmtCmd("pib", "add-nexthop", &mgmt_2022.ControlArgs{
		Name: args.Name,
		Cost: optional.Some(uint64(args.Cost)),
	})
	if err != nil {
		log.Warn(c, "Failed to register prefix", "err", err)
		if args.OnError != nil {
			args.OnError(err)
		}
	} else {
		log.Info(c, "Registered prefix", "name", args.Name)
	}
}

// (AI GENERATED DESCRIPTION): Withdraws a previously announced prefix from the local PIB by issuing a “pib remove‑nexthop” command and logs the result.
func (c *Client) withdrawPrefix_(args ndn.Announcement, onError func(error)) {
	announceMutex.Lock()
	time.Sleep(1 * time.Millisecond) // thanks NFD
	announceMutex.Unlock()

	_, err := c.engine.ExecMgmtCmd("pib", "remove-nexthop", &mgmt_2022.ControlArgs{
		Name: args.Name,
	})
	if err != nil {
		log.Warn(c, "Failed to unregister prefix", "err", err)
		if onError != nil {
			onError(err)
		}
	} else {
		log.Info(c, "Unregistered prefix", "name", args.Name)
	}
}

// (AI GENERATED DESCRIPTION): Re‑issues all stored announcements asynchronously when the Face comes up, stopping the iteration if the Face ever stops running.
func (c *Client) onFaceUp() {
	go func() {
		c.announcements.Range(func(key, value any) bool {
			c.announcePrefix_(value.(ndn.Announcement))
			return c.engine.Face().IsRunning()
		})
	}()
}

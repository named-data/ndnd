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

// (AI GENERATED DESCRIPTION): Announces a prefix to the network by registering it with the routing information base (RIB), optionally exposing it and setting its cost, and spacing the request with a short delay to accommodate NFD behavior.
func (c *Client) announcePrefix_(args ndn.Announcement) {
	announceMutex.Lock()
	time.Sleep(1 * time.Millisecond) // thanks NFD
	announceMutex.Unlock()

	origin := optional.None[uint64]()
	if args.Expose {
		origin = optional.Some(uint64(mgmt_2022.RouteOriginClient))
	}

	_, err := c.engine.ExecMgmtCmd("rib", "register", &mgmt_2022.ControlArgs{
		Name:   args.Name,
		Origin: origin,
		Cost:   optional.Some(uint64(args.Cost)),
	})
	if err != nil {
		log.Warn(c, "Failed to register route", "err", err)
		if args.OnError != nil {
			args.OnError(err)
		}
	} else {
		log.Info(c, "Registered route", "name", args.Name)
	}
}

// (AI GENERATED DESCRIPTION): Withdraws a previously announced prefix from the local NFD’s RIB (optionally marking it as client‑originated) by issuing an “rib unregister” command and logs the result.
func (c *Client) withdrawPrefix_(args ndn.Announcement, onError func(error)) {
	announceMutex.Lock()
	time.Sleep(1 * time.Millisecond) // thanks NFD
	announceMutex.Unlock()

	origin := optional.None[uint64]()
	if args.Expose {
		origin = optional.Some(uint64(mgmt_2022.RouteOriginClient))
	}

	_, err := c.engine.ExecMgmtCmd("rib", "unregister", &mgmt_2022.ControlArgs{
		Name:   args.Name,
		Origin: origin,
	})
	if err != nil {
		log.Warn(c, "Failed to unregister route", "err", err)
		if onError != nil {
			onError(err)
		}
	} else {
		log.Info(c, "Unregistered route", "name", args.Name)
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

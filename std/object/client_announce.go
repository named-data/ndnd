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

func (c *Client) AnnouncePrefix(args ndn.Announcement) {
	hash := args.Name.TlvStr()
	c.announcements.Store(hash, args)

	if c.engine.Face().IsRunning() {
		go c.announcePrefix_(args)
	}
}

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

func (c *Client) onFaceUp() {
	go func() {
		c.announcements.Range(func(key, value any) bool {
			c.announcePrefix_(value.(ndn.Announcement))
			return c.engine.Face().IsRunning()
		})
	}()
}

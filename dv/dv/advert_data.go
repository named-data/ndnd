package dv

import (
	"time"

	"github.com/named-data/ndnd/dv/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
)

func (a *advertModule) generate() {
	a.dv.mutex.Lock()
	defer a.dv.mutex.Unlock()

	// Increment sequence number
	a.seq++

	// Produce the advertisement
	name := a.dv.config.AdvertisementDataPrefix().
		Append(enc.NewTimestampComponent(a.bootTime)).
		WithVersion(a.seq)
	name, err := a.dv.client.Produce(ndn.ProduceArgs{
		Name:            name,
		Content:         a.dv.rib.Advert().Encode(),
		FreshnessPeriod: 10 * time.Second,
	})
	if err != nil {
		log.Error(a, "Failed to produce advertisement", "err", err)
	}
	a.objDir.Push(name)
	a.objDir.Evict(a.dv.client)

	// Notify neighbors with sync for new advertisement
	go a.sendSyncInterest()
}

func (a *advertModule) dataFetch(nName enc.Name, bootTime uint64, seqNo uint64) {
	// debounce; wait before fetching, then check if this is still the latest
	// sequence number known for this neighbor
	time.Sleep(10 * time.Millisecond)
	if ns := a.dv.neighbors.Get(nName); ns == nil || ns.AdvertBoot != bootTime || ns.AdvertSeq != seqNo {
		return
	}

	// Fetch the advertisement
	advName := enc.LOCALHOP.
		Append(nName...).
		Append(enc.NewKeywordComponent("DV")).
		Append(enc.NewKeywordComponent("ADV")).
		Append(enc.NewTimestampComponent(bootTime)).
		WithVersion(seqNo)

	a.dv.client.Consume(advName, func(state ndn.ConsumeState) {
		if !state.IsComplete() {
			return
		}

		go func() {
			fetchErr := state.Error()
			if fetchErr != nil {
				log.Warn(a, "Failed to fetch advertisement", "name", state.Name(), "err", fetchErr)
				time.Sleep(1 * time.Second) // wait on error
				a.dataFetch(nName, bootTime, seqNo)
				return
			}

			// Process the advertisement
			a.dataHandler(nName, seqNo, state.Content())
		}()
	})
}

// Received advertisement Data
func (a *advertModule) dataHandler(nName enc.Name, seqNo uint64, data enc.Wire) {
	// Lock DV state
	a.dv.mutex.Lock()
	defer a.dv.mutex.Unlock()

	// Check if this is the latest advertisement
	ns := a.dv.neighbors.Get(nName)
	if ns == nil {
		log.Warn(a, "Unknown advertisement", "name", nName)
		return
	}
	if ns.AdvertSeq != seqNo {
		log.Debug(a, "Old advertisement", "name", nName, "want", ns.AdvertSeq, "have", seqNo)
		return
	}

	// Parse the advertisement
	advert, err := tlv.ParseAdvertisement(enc.NewFastReader(data), false)
	if err != nil {
		log.Error(a, "Failed to parse advertisement", "err", err)
		return
	}

	// Update the local advertisement list
	ns.Advert = advert
	go a.dv.ribUpdate(ns)
}

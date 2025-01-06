package dv

import (
	"time"

	"github.com/named-data/ndnd/dv/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/object"
	"github.com/named-data/ndnd/std/utils"
)

func (dv *Router) advertGenerateNew() {
	dv.mutex.Lock()
	defer dv.mutex.Unlock()

	// Increment sequence number
	dv.advertSyncSeq++

	// Produce the advertisement
	name, err := dv.client.Produce(object.ProduceArgs{
		Name:            dv.config.AdvertisementDataPrefix(),
		Content:         dv.rib.Advert().Encode(),
		Version:         utils.IdPtr(dv.advertSyncSeq),
		FreshnessPeriod: 10 * time.Second,
	})
	if err != nil {
		log.Errorf("advert-data: failed to produce advertisement: %+v", err)
	}
	dv.advertDir.Push(name)
	dv.advertDir.Evict(dv.client)

	// Notify neighbors with sync for new advertisement
	go dv.advertSyncSendInterest()
}

func (dv *Router) advertDataFetch(nodeId enc.Name, seqNo uint64) {
	// debounce; wait before fetching, then check if this is still the latest
	// sequence number known for this neighbor
	time.Sleep(10 * time.Millisecond)
	if ns := dv.neighbors.Get(nodeId); ns == nil || ns.AdvertSeq != seqNo {
		return
	}

	// Fetch the advertisement
	advName := enc.LOCALHOP.Append(nodeId.Append(
		enc.NewStringComponent(enc.TypeKeywordNameComponent, "DV"),
		enc.NewStringComponent(enc.TypeKeywordNameComponent, "ADV"),
		enc.NewVersionComponent(seqNo),
	)...)

	dv.client.Consume(advName, func(state *object.ConsumeState) bool {
		if !state.IsComplete() {
			return true
		}

		go func() {
			fetchErr := state.Error()
			if fetchErr != nil {
				log.Warnf("advert-data: failed to fetch advertisement %s: %+v", state.Name(), fetchErr)
				time.Sleep(1 * time.Second) // wait on error
				dv.advertDataFetch(nodeId, seqNo)
				return
			}

			// Process the advertisement
			dv.advertDataHandler(nodeId, seqNo, state.Content())
		}()

		return true
	})
}

// Received advertisement Data
func (dv *Router) advertDataHandler(nodeId enc.Name, seqNo uint64, data []byte) {
	// Lock DV state
	dv.mutex.Lock()
	defer dv.mutex.Unlock()

	// Check if this is the latest advertisement
	ns := dv.neighbors.Get(nodeId)
	if ns == nil {
		log.Warnf("advert-handler: unknown advertisement %s", nodeId)
		return
	}
	if ns.AdvertSeq != seqNo {
		log.Debugf("advert-handler: old advertisement for %s (%d != %d)", nodeId, ns.AdvertSeq, seqNo)
		return
	}

	// Parse the advertisement
	advert, err := tlv.ParseAdvertisement(enc.NewBufferReader(data), false)
	if err != nil {
		log.Errorf("advert-handler: failed to parse advertisement: %+v", err)
		return
	}

	// Update the local advertisement list
	ns.Advert = advert
	go dv.ribUpdate(ns)
}

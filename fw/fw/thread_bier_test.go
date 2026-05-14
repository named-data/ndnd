package fw

import (
	"bytes"
	"testing"

	"github.com/named-data/ndnd/fw/bier"
	"github.com/named-data/ndnd/fw/defn"
	"github.com/named-data/ndnd/fw/table"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/types/optional"
)

func TestHandleMulticastPipelineBitstringResolution(t *testing.T) {
	original := bier.Bift
	bift := &bier.BiftState{}
	bier.Bift = bift
	defer func() {
		bier.Bift = original
	}()

	thread := &Thread{}
	lookup, _ := enc.NameFromStr("/ndn/svs/32=svs")

	t.Run("Transit preserves existing bitstring without PET", func(t *testing.T) {
		packet := &defn.Pkt{Bier: []byte{0x24, 0x01}}

		thread.handleMulticastPipeline(pipelineContext{
			Pkt:        packet,
			PetEntry:   table.PetEntry{},
			PetFound:   false,
			LookupName: lookup,
		})

		if !bytes.Equal(packet.Bier, []byte{0x24, 0x01}) {
			t.Fatalf("transit bitstring changed: got %v", packet.Bier)
		}
	})

	t.Run("Ingress builds bitstring from PET egress routers", func(t *testing.T) {
		r1 := enc.Name{enc.NewGenericComponent("router1")}
		r3 := enc.Name{enc.NewGenericComponent("router3")}
		bift.RegisterRouter(r1, 1)
		bift.RegisterRouter(r3, 3)

		packet := &defn.Pkt{}
		thread.handleMulticastPipeline(pipelineContext{
			Pkt: packet,
			PetEntry: table.PetEntry{
				EgressRouters: []enc.Name{r1, r3},
			},
			PetFound:   true,
			LookupName: lookup,
		})

		if !bier.BierGetBit(packet.Bier, 1) {
			t.Fatal("expected bit 1 to be set for router1")
		}
		if !bier.BierGetBit(packet.Bier, 3) {
			t.Fatal("expected bit 3 to be set for router3")
		}
		if bier.BierGetBit(packet.Bier, 0) || bier.BierGetBit(packet.Bier, 2) {
			t.Fatal("unexpected extra bits set in ingress-generated bitstring")
		}
	})

	t.Run("Missing PET and missing bitstring leaves packet unchanged", func(t *testing.T) {
		packet := &defn.Pkt{}
		thread.handleMulticastPipeline(pipelineContext{
			Pkt:        packet,
			PetEntry:   table.PetEntry{},
			PetFound:   false,
			LookupName: lookup,
		})

		if packet.Bier != nil {
			t.Fatalf("expected nil bitstring when neither PET nor BIER state is available, got %v", packet.Bier)
		}
	})
}

func TestCollectPetLocalHops(t *testing.T) {
	name, _ := enc.NameFromStr("/ndn/svs/32=svs")
	interest := &defn.FwInterest{
		NameV:  name,
		NonceV: optional.Some(uint32(1)),
	}

	makePitEntry := func() table.PitEntry {
		pitCS := table.NewPitCS(func(table.PitEntry) {})
		pitEntry, _ := pitCS.InsertInterest(interest, nil, 99)
		pitEntry.InsertInRecord(interest, 10, []byte("local"))
		return pitEntry
	}

	localHop := table.PetNextHop{FaceID: 10, Cost: 0}
	thread := &Thread{}

	t.Run("multicast keeps local egress despite pending local in-record", func(t *testing.T) {
		hops := thread.collectPetLocalHops(petLocalHopsContext{
			Packet:   &defn.Pkt{IncomingFaceID: 99},
			Pipeline: fwMulticastEgress,
			PitEntry: makePitEntry(),
			PetEntry: table.PetEntry{
				NextHops: []table.PetNextHop{localHop},
			},
			PetFound:   true,
			LookupName: name,
		})

		if len(hops) != 1 || hops[0].FaceID != localHop.FaceID {
			t.Fatalf("expected multicast local hop %d to be preserved, got %+v", localHop.FaceID, hops)
		}
	})

	t.Run("unicast still suppresses pending local in-record", func(t *testing.T) {
		hops := thread.collectPetLocalHops(petLocalHopsContext{
			Packet:   &defn.Pkt{IncomingFaceID: 99},
			Pipeline: fwUnicastEgress,
			PitEntry: makePitEntry(),
			PetEntry: table.PetEntry{
				NextHops: []table.PetNextHop{localHop},
			},
			PetFound:   true,
			LookupName: name,
		})

		if len(hops) != 0 {
			t.Fatalf("expected unicast local hop to stay suppressed, got %+v", hops)
		}
	})
}

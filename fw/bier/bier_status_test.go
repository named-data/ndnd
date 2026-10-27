package bier_test

import (
	"testing"

	"github.com/named-data/ndnd/fw/bier"
	enc "github.com/named-data/ndnd/std/encoding"
)

func TestBiftStatusOwnsSnapshot(t *testing.T) {
	state := &bier.BiftState{}
	name := enc.Name{enc.NewGenericComponent("router")}
	state.RegisterRouter(name, 0)
	state.UpdateNextHop(0, 100)
	state.RebuildFbm()

	status := state.Status()
	status.Entries[0].RouterName[0].Val[0] = 'X'
	status.Entries[0].FbmBits[0] = 7
	if status.Neighbors[0].FbmBits[0] != 0 {
		t.Fatal("entry and neighbor masks share mutable storage")
	}
	again := state.Status()
	if !again.Entries[0].RouterName.Equal(name) || again.Entries[0].FbmBits[0] != 0 {
		t.Fatal("modifying a snapshot changed live BIFT state")
	}
}

func TestBiftStatusConsistentDuringUpdates(t *testing.T) {
	state := &bier.BiftState{}
	state.RegisterRouter(enc.Name{enc.NewGenericComponent("router")}, 0)
	state.UpdateNextHop(0, 100)
	state.RebuildFbm()

	stop, started, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		close(started)
		for face := uint64(100); ; face = 300 - face {
			select {
			case <-stop:
				return
			default:
				state.UpdateNextHop(0, face)
			}
		}
	}()
	<-started
	defer func() { close(stop); <-done }()
	for range 1000 {
		status := state.Status()
		if len(status.Entries) != 1 || len(status.Neighbors) != 1 {
			t.Fatal("snapshot lost its entry or neighbor")
		}
		if status.Entries[0].NextHops[0] != status.Neighbors[0].FaceID {
			t.Fatal("entry and neighbor came from different BIFT states")
		}
	}
}

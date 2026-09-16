package table

import (
	"fmt"
	"testing"

	"github.com/named-data/ndnd/fw/core"
	"github.com/named-data/ndnd/fw/defn"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/stretchr/testify/assert"
)

func lruTestData(nameStr string) *defn.FwData {
	name, err := enc.NameFromStr(nameStr)
	if err != nil {
		panic(err)
	}
	return &defn.FwData{NameV: name}
}

func TestCsLRUEvictionForgetsLocations(t *testing.T) {
	core.C.Tables.ContentStore.ReplacementPolicy = "lru"
	core.C.Tables.Fib.Algorithm = "nametree"
	Initialize()
	CfgSetCsCapacity(5)

	pitCS := NewPitCS(func(PitEntry) {})
	lru := pitCS.csReplacement.(*CsLRU)

	// Insert 100 distinct CS entries; 95 must be evicted to respect capacity.
	for i := 0; i < 100; i++ {
		data := lruTestData(fmt.Sprintf("/ndnd/test/lru/%d", i))
		pitCS.InsertData(data, []byte{0x06, 0x00})
	}

	assert.Equal(t, 5, pitCS.CsSize())
	assert.Equal(t, 5, lru.queue.Len())
	// The locations index must not outlive the entries it tracks.
	assert.Equal(t, lru.queue.Len(), len(lru.locations),
		"CsLRU.locations keeps stale entries after eviction (memory leak)")
}

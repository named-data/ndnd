package sync_test

import (
	"testing"

	ndn_sync "github.com/named-data/ndnd/std/sync"
	"github.com/named-data/ndnd/std/utils"
	"github.com/stretchr/testify/require"
)

func makeSvMap() ndn_sync.SvMap {
	m := ndn_sync.NewSvMap(0)
	m.Set("/ndn/alice", 100, 1)
	m.Set("/ndn/alice", 200, 4)
	m.Set("/ndn/bob", 150, 3)
	return m
}

func TestSvMapBasic(t *testing.T) {
	utils.SetTestingT(t)

	m := makeSvMap()

	// Basic entries
	require.Equal(t, uint64(1), m.Get("/ndn/alice", 100).SeqNo)
	require.Equal(t, uint64(4), m.Get("/ndn/alice", 200).SeqNo)
	require.Equal(t, uint64(3), m.Get("/ndn/bob", 150).SeqNo)

	// Empty entries
	require.Equal(t, uint64(0), m.Get("/ndn/bob", 100).SeqNo)
	require.Equal(t, uint64(0), m.Get("/ndn/cathy", 100).SeqNo)

	// Update entries
	m.Set("/ndn/bob", 150, 5)
	require.Equal(t, uint64(5), m.Get("/ndn/bob", 150).SeqNo)
}

func TestSvMapNewer(t *testing.T) {
	utils.SetTestingT(t)

	m1 := makeSvMap()
	m2 := makeSvMap()

	// Equal
	require.False(t, m1.IsNewerThan(m2, false))
	require.False(t, m1.IsNewerThan(m2, true))

	// Different sequence number
	m2.Set("/ndn/alice", 200, 99)
	require.True(t, m2.IsNewerThan(m1, false))
	require.False(t, m2.IsNewerThan(m1, true))
	require.False(t, m1.IsNewerThan(m2, false))
	require.False(t, m1.IsNewerThan(m2, true))

	// Different entry exist
	m2.Set("/ndn/cathy", 100, 99)
	require.True(t, m2.IsNewerThan(m1, false))
	require.True(t, m2.IsNewerThan(m1, true))
	require.False(t, m1.IsNewerThan(m2, false))
	require.False(t, m1.IsNewerThan(m2, true))

	// Both are new (m1 seq only)
	m1.Set("/ndn/bob", 150, 99)
	require.True(t, m2.IsNewerThan(m1, false))
	require.True(t, m2.IsNewerThan(m1, true))
	require.True(t, m1.IsNewerThan(m2, false))
	require.False(t, m1.IsNewerThan(m2, true))
}

func TestSvMapTLV(t *testing.T) {
	utils.SetTestingT(t)

	// Add entries to test ordering
	m := ndn_sync.NewSvMap(0)
	m.Set("/ndn/alice", 100, 1)
	m.Set("/ndn/alice", 200, 4)
	m.Set("/ndn/cathy", 150, 3)
	m.Set("/ndn/bob", 150, 3)
	m.Set("/ndn/bob", 50, 5)
	sv := m.Encode()

	// Name Ordering should be in NDN canonical order.
	// Bootstrap time is in ascending order.
	// https://docs.named-data.net/NDN-packet-spec/current/name.html#canonical-order

	bob := sv.Entries[0]
	require.Equal(t, "/ndn/bob", bob.Name.String())
	require.Equal(t, uint64(50), bob.SeqNoEntries[0].BootstrapTime)
	require.Equal(t, uint64(5), bob.SeqNoEntries[0].SeqNo)
	require.Equal(t, uint64(150), bob.SeqNoEntries[1].BootstrapTime)
	require.Equal(t, uint64(3), bob.SeqNoEntries[1].SeqNo)

	alice := sv.Entries[1]
	require.Equal(t, "/ndn/alice", alice.Name.String())
	require.Equal(t, uint64(100), alice.SeqNoEntries[0].BootstrapTime)
	require.Equal(t, uint64(1), alice.SeqNoEntries[0].SeqNo)
	require.Equal(t, uint64(200), alice.SeqNoEntries[1].BootstrapTime)
	require.Equal(t, uint64(4), alice.SeqNoEntries[1].SeqNo)

	cathy := sv.Entries[2]
	require.Equal(t, "/ndn/cathy", cathy.Name.String())
	require.Equal(t, uint64(150), cathy.SeqNoEntries[0].BootstrapTime)
	require.Equal(t, uint64(3), cathy.SeqNoEntries[0].SeqNo)
}

package dv

import (
	"encoding/hex"
	"slices"
	"testing"

	"github.com/named-data/ndnd/dv/table"
	"github.com/named-data/ndnd/dv/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/stretchr/testify/require"
)

func TestPrefixStateStatusWireSpecification(t *testing.T) {
	wire, err := hex.DecodeString("fd019f0101fd01a11a0703080170fd01a303080172fd01a500fd01a7066901086a0103")
	require.NoError(t, err)
	status, err := tlv.ParsePrefixStateStatus(enc.NewWireView(enc.Wire{wire}), false)
	require.NoError(t, err)
	require.Equal(t, tlv.PrefixStateStatusVersion, status.Version)
	require.Len(t, status.Entries, 1)
	require.Equal(t, "/p", status.Entries[0].Name.String())
	require.Equal(t, "/r", status.Entries[0].Router.String())
	require.True(t, status.Entries[0].Multicast)
	require.Equal(t, uint64(8), status.Entries[0].NextHops[0].Face)
	require.Equal(t, uint64(3), status.Entries[0].NextHops[0].Cost)
	require.Equal(t, wire, status.Encode().Join())

	for _, test := range []struct {
		name  string
		wire  string
		valid bool
	}{
		{"empty snapshot", "fd019f0101", true},
		{"unknown non-critical", "fd019f0101fd01fe00", true},
		{"unknown critical", "fd019f0101fd01ff00", false},
		{"missing version", "", false},
		{"truncated version", "fd019f0201", false},
		{"nested unknown critical", "fd019f0101fd01a1100703080170fd01a303080172fd01ff00", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire, err := hex.DecodeString(test.wire)
			require.NoError(t, err)
			_, err = tlv.ParsePrefixStateStatus(enc.NewWireView(enc.Wire{wire}), false)
			if test.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestMakePrefixStateStatusDeterministic(t *testing.T) {
	nameA, err := enc.NameFromStr("/example/a")
	require.NoError(t, err)
	nameB, err := enc.NameFromStr("/example/b")
	require.NoError(t, err)
	routerA, err := enc.NameFromStr("/router/a")
	require.NoError(t, err)
	routerB, err := enc.NameFromStr("/router/b")
	require.NoError(t, err)

	entries := []table.PrefixSnapshotEntry{
		{Name: nameB, Router: routerB},
		{
			Name:           nameA,
			Router:         routerB,
			Multicast:      true,
			ValidityPeriod: &spec.ValidityPeriod{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"},
			NextHops:       []table.PrefixNextHop{{Face: 9, Cost: 2}, {Face: 3, Cost: 4}},
		},
		{Name: nameA, Router: routerA},
	}
	first := makePrefixStateStatus(slices.Clone(entries)).Encode().Join()
	slices.Reverse(entries)
	second := makePrefixStateStatus(entries).Encode().Join()
	require.Equal(t, first, second)

	decoded, err := tlv.ParsePrefixStateStatus(enc.NewWireView(enc.Wire{first}), false)
	require.NoError(t, err)
	require.Equal(t, tlv.PrefixStateStatusVersion, decoded.Version)
	require.Len(t, decoded.Entries, 3)
	require.Equal(t, nameA, decoded.Entries[0].Name)
	require.Equal(t, routerA, decoded.Entries[0].Router)
	require.True(t, decoded.Entries[1].Multicast)
	require.Equal(t, "2027-01-01T00:00:00Z", decoded.Entries[1].ValidityPeriod.NotAfter)
	require.Equal(t, uint64(3), decoded.Entries[1].NextHops[0].Face)
}

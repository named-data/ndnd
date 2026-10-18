package mgmt

import (
	"encoding/hex"
	"testing"

	"github.com/named-data/ndnd/fw/bier"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/stretchr/testify/require"
)

func TestBiftStatusWireSpecification(t *testing.T) {
	wire, err := hex.DecodeString("fd02590101fd025a0107fd025b190703080172fd025f0103fd0261010cfd02630101fd02630104fd025d0869010cfd02650101")
	require.NoError(t, err)
	status, err := mgmt_2022.ParseBiftStatusMsg(enc.NewWireView(enc.Wire{wire}), false)
	require.NoError(t, err)
	require.Equal(t, mgmt_2022.BiftStatusVersion, status.Version)
	require.Equal(t, uint64(7), status.BierIndex.Unwrap())
	require.Len(t, status.Entries, 1)
	require.Equal(t, "/r", status.Entries[0].RouterName.String())
	require.Equal(t, uint64(3), status.Entries[0].BfrId)
	require.Equal(t, []uint64{12}, status.Entries[0].NextHops)
	require.Equal(t, []uint64{1, 4}, status.Entries[0].FbmBits)
	require.Equal(t, uint64(12), status.Neighbors[0].FaceId)
	require.Equal(t, []uint64{1}, status.Neighbors[0].FbmBits)
	require.Equal(t, wire, status.Encode().Join())

	for _, test := range []struct {
		name  string
		wire  string
		valid bool
	}{
		{"empty snapshot", "fd02590101", true},
		{"unknown non-critical", "fd02590101fd02fe00", true},
		{"unknown critical", "fd02590101fd02ff00", false},
		{"missing version", "", false},
		{"truncated version", "fd02590201", false},
		{"nested unknown critical", "fd02590101fd025b0e0703080172fd025f0103fd02ff00", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire, err := hex.DecodeString(test.wire)
			require.NoError(t, err)
			_, err = mgmt_2022.ParseBiftStatusMsg(enc.NewWireView(enc.Wire{wire}), false)
			if test.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestMakeBiftStatusEncodesSnapshot(t *testing.T) {
	status, err := makeBiftStatus(bier.BiftStatus{
		BierIndex: -1,
		Entries: []bier.BiftStatusEntry{{
			BfrId:      3,
			RouterName: "/ndn/router",
			NextHops:   []uint64{12},
			FbmBits:    []int{1, 4},
		}},
		Neighbors: []bier.BiftStatusNeighbor{{FaceID: 12, FbmBits: []int{1, 4}}},
	})
	require.NoError(t, err)
	require.Equal(t, mgmt_2022.BiftStatusVersion, status.Version)
	require.False(t, status.BierIndex.IsSet())

	decoded, err := mgmt_2022.ParseBiftStatusMsg(enc.NewWireView(status.Encode()), true)
	require.NoError(t, err)
	require.Len(t, decoded.Entries, 1)
	require.Equal(t, uint64(3), decoded.Entries[0].BfrId)
	require.Equal(t, "/ndn/router", decoded.Entries[0].RouterName.String())
	require.Equal(t, []uint64{1, 4}, decoded.Entries[0].FbmBits)
	require.Equal(t, uint64(12), decoded.Neighbors[0].FaceId)
}

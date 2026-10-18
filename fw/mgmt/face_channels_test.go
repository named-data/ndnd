package mgmt

import (
	"testing"

	enc "github.com/named-data/ndnd/std/encoding"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/stretchr/testify/require"
)

func TestChannelStatusDataset(t *testing.T) {
	module := &FaceModule{channelURIs: []string{
		"udp://0.0.0.0:6364",
		"ws://0.0.0.0:9696",
	}}

	encoded := module.channelStatusDataset().Encode()
	require.Equal(t, byte(0x82), encoded.Join()[0])
	dataset, err := mgmt.ParseChannelStatusMsg(enc.NewWireView(encoded), true)
	require.NoError(t, err)
	require.Len(t, dataset.Vals, 2)
	require.Equal(t, []string{
		"udp://0.0.0.0:6364",
		"ws://0.0.0.0:9696",
	}, []string{dataset.Vals[0].LocalUri, dataset.Vals[1].LocalUri})
}

package dv

import (
	"testing"
	"time"

	"github.com/named-data/ndnd/dv/config"
	"github.com/named-data/ndnd/dv/table"
	"github.com/named-data/ndnd/dv/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	basic_engine "github.com/named-data/ndnd/std/engine/basic"
	"github.com/named-data/ndnd/std/engine/face"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/stretchr/testify/require"
)

func TestPrefixListManagementReturnsVersionedTLV(t *testing.T) {
	dvConfig := config.DefaultConfig()
	dvConfig.Network = "/ndn"
	dvConfig.Router = "/ndn/router-a"
	require.NoError(t, dvConfig.Parse())

	prefix, err := enc.NameFromStr("/ndn/example")
	require.NoError(t, err)
	state := table.NewPrefixState(dvConfig, func(enc.Wire) {})
	state.Announce(prefix, 7, 3, true, nil)

	interestName := enc.Name{
		enc.LOCALHOST,
		enc.NewGenericComponent("dv"),
		enc.NewGenericComponent("prefix"),
		enc.NewGenericComponent("list"),
	}
	dummyFace := face.NewDummyFace()
	engine := basic_engine.NewEngine(dummyFace, basic_engine.NewDummyTimer())
	require.NoError(t, engine.Start())
	defer func() { require.NoError(t, engine.Stop()) }()

	router := &Router{
		config: dvConfig,
		pfx:    &PrefixModule{pfx: state},
		engine: engine,
	}
	require.NoError(t, engine.AttachHandler(dvConfig.MgmtPrefix(), func(args ndn.InterestHandlerArgs) {
		router.mgmtOnInterest(args)
	}))
	interest, err := engine.Spec().MakeInterest(interestName, &ndn.InterestConfig{
		MustBeFresh: true,
		Lifetime:    optional.Some(time.Second),
		Nonce:       optional.Some(uint32(1)),
	}, nil, nil)
	require.NoError(t, err)
	responses := make(chan ndn.ExpressCallbackArgs, 1)
	require.NoError(t, engine.Express(interest, func(args ndn.ExpressCallbackArgs) { responses <- args }))

	requestWire, err := dummyFace.Consume()
	require.NoError(t, err)
	require.NoError(t, dummyFace.FeedPacket(requestWire))
	replyWire, err := dummyFace.Consume()
	require.NoError(t, err)
	require.NoError(t, dummyFace.FeedPacket(replyWire))
	response := <-responses
	require.Equal(t, ndn.InterestResultData, response.Result)

	data, _, err := (spec_2022.Spec{}).ReadData(enc.NewWireView(response.RawData))
	require.NoError(t, err)
	require.Equal(t, interestName, data.Name())
	status, err := tlv.ParsePrefixStateStatus(enc.NewWireView(data.Content()), false)
	require.NoError(t, err)
	require.Equal(t, tlv.PrefixStateStatusVersion, status.Version)
	require.Len(t, status.Entries, 1)
	require.Equal(t, prefix, status.Entries[0].Name)
	require.Equal(t, dvConfig.RouterName(), status.Entries[0].Router)
	require.True(t, status.Entries[0].Multicast)
	require.Equal(t, uint64(7), status.Entries[0].NextHops[0].Face)
	require.Equal(t, uint64(3), status.Entries[0].NextHops[0].Cost)
}

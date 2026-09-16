package fw

import (
	"testing"

	"github.com/named-data/ndnd/fw/core"
	"github.com/named-data/ndnd/fw/defn"
	"github.com/named-data/ndnd/fw/dispatch"
	"github.com/named-data/ndnd/fw/table"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/stretchr/testify/assert"
)

type fakeFace struct {
	id   uint64
	sent []dispatch.OutPkt
}

func (f *fakeFace) String() string                 { return "fakeFace" }
func (f *fakeFace) SetFaceID(faceID uint64)        { f.id = faceID }
func (f *fakeFace) FaceID() uint64                 { return f.id }
func (f *fakeFace) LocalURI() *defn.URI            { return nil }
func (f *fakeFace) RemoteURI() *defn.URI           { return nil }
func (f *fakeFace) Scope() defn.Scope              { return defn.NonLocal }
func (f *fakeFace) LinkType() defn.LinkType        { return defn.PointToPoint }
func (f *fakeFace) MTU() int                       { return 9000 }
func (f *fakeFace) State() defn.State              { return defn.Up }
func (f *fakeFace) SendPacket(out dispatch.OutPkt) { f.sent = append(f.sent, out) }

func mkInterest(nameStr string, canBePrefix bool, nonce uint32) *defn.FwInterest {
	name, err := enc.NameFromStr(nameStr)
	if err != nil {
		panic(err)
	}
	return &defn.FwInterest{
		NameV:        name,
		CanBePrefixV: canBePrefix,
		NonceV:       optional.Some(nonce),
	}
}

func TestDataMultiPitMatchDeadNonceList(t *testing.T) {
	core.C.Tables.ContentStore.ReplacementPolicy = "lru"
	core.C.Tables.Fib.Algorithm = "nametree"
	table.Initialize()
	table.CfgSetCsAdmit(false)
	table.CfgSetCsServe(false)

	thread := NewThread(0)

	downstream := &fakeFace{id: 100}
	upstream := &fakeFace{id: 200}
	dispatch.AddFace(100, downstream)
	dispatch.AddFace(200, upstream)
	defer dispatch.RemoveFace(100)
	defer dispatch.RemoveFace(200)

	// Two pending interests that both match Data /a/b:
	//  /a   (CanBePrefix=true),  nonce 1111
	//  /a/b (CanBePrefix=false), nonce 2222
	// Both were forwarded upstream (face 200) with their respective nonces.
	interestA := mkInterest("/a", true, 1111)
	pitEntryA, _ := thread.pitCS.InsertInterest(interestA, nil, downstream.id)
	pitEntryA.InsertInRecord(interestA, downstream.id, nil)
	pitEntryA.InsertOutRecord(interestA, upstream.id)

	interestB := mkInterest("/a/b", false, 2222)
	pitEntryB, _ := thread.pitCS.InsertInterest(interestB, nil, downstream.id)
	pitEntryB.InsertInRecord(interestB, downstream.id, nil)
	pitEntryB.InsertOutRecord(interestB, upstream.id)

	// Data /a/b arrives from upstream.
	dataName, _ := enc.NameFromStr("/a/b")
	packet := &defn.Pkt{
		Name:           dataName,
		L3:             &defn.FwPacket{Data: &defn.FwData{NameV: dataName}},
		IncomingFaceID: upstream.id,
	}
	thread.processIncomingData(packet)

	// Both entries got satisfied and data went downstream.
	assert.Equal(t, 2, len(downstream.sent))

	// The out-nonces of BOTH satisfied PIT entries must be in the dead nonce
	// list, so a looped interest carrying either nonce is dropped.
	assert.True(t, thread.deadNonceList.Find(dataName, 2222), "nonce of /a/b entry missing from DNL")
	assert.True(t, thread.deadNonceList.Find(dataName, 1111), "nonce of /a entry missing from DNL")
}

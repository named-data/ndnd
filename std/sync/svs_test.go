package sync

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	spec_svs "github.com/named-data/ndnd/std/ndn/svs/v3"
	sig "github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/types/optional"
	tu "github.com/named-data/ndnd/std/utils/testutils"
)

// --- shared test helpers and encode tests ---

func testSvMapAliceBob() SvMap[uint64] {
	m := NewSvMap[uint64](0)
	m.Set(tu.NoErr(enc.NameFromStr("/ndn/alice")).TlvStr(), 100, 5)
	m.Set(tu.NoErr(enc.NameFromStr("/ndn/bob")).TlvStr(), 150, 3)
	return m
}

func TestBuildInlineFullSvsData(t *testing.T) {
	tu.SetT(t)

	m := testSvMapAliceBob()
	sv := m.Encode(func(s uint64) uint64 { return s })
	data := &spec_svs.SvsData{
		MemberSetHash: ComputeMembershipHash(m),
		VectorType:    optional.Some(spec_svs.VectorTypeFull),
		StateVector:   sv,
	}

	require.Equal(t, ComputeMembershipHash(m), data.MemberSetHash)
	vt, ok := data.VectorType.Get()
	require.True(t, ok)
	require.Equal(t, spec_svs.VectorTypeFull, vt)
	require.NotNil(t, data.StateVector)
	require.Len(t, data.StateVector.Entries, 2)
}

func TestOnReceivePartialSkipsMissingNameOutdated(t *testing.T) {
	tu.SetT(t)

	s := &SvSync{
		o: SvSyncOpts{
			OnUpdate:          func(SvSyncUpdate) {},
			SuppressionPeriod: 200 * time.Millisecond,
			PeriodicTimeout:   30 * time.Second,
		},
		state:    testSvMapAliceBob(),
		mtime:    make(map[string]time.Time),
		ticker:   time.NewTicker(30 * time.Second),
		suppress: false,
	}

	// PARTIAL with only bob; local knows alice — must not enter suppression.
	bobOnly := NewSvMap[uint64](0)
	bobOnly.Set(tu.NoErr(enc.NameFromStr("/ndn/bob")).TlvStr(), 150, 3)
	partialSv := bobOnly.Encode(func(s uint64) uint64 { return s })

	s.onReceiveStateVector(svSyncRecvSvArgs{
		sv:         partialSv,
		vectorType: optional.Some(spec_svs.VectorTypePartial),
		mhash:      ComputeMembershipHash(bobOnly),
	})

	require.False(t, s.suppress)
}

func TestOnReceiveFullTreatsMissingNameOutdated(t *testing.T) {
	tu.SetT(t)

	s := &SvSync{
		o: SvSyncOpts{
			OnUpdate:          func(SvSyncUpdate) {},
			SuppressionPeriod: 200 * time.Millisecond,
			PeriodicTimeout:   30 * time.Second,
		},
		state:    testSvMapAliceBob(),
		mtime:    make(map[string]time.Time),
		ticker:   time.NewTicker(30 * time.Second),
		suppress: false,
	}

	bobOnly := NewSvMap[uint64](0)
	bobOnly.Set(tu.NoErr(enc.NameFromStr("/ndn/bob")).TlvStr(), 150, 3)
	fullSv := bobOnly.Encode(func(s uint64) uint64 { return s })

	s.onReceiveStateVector(svSyncRecvSvArgs{
		sv:         fullSv,
		vectorType: optional.Some(spec_svs.VectorTypeFull),
		mhash:      ComputeMembershipHash(bobOnly),
	})

	require.True(t, s.suppress)
}

func TestEncodePartialSenderFirst(t *testing.T) {
	tu.SetT(t)

	alice := tu.NoErr(enc.NameFromStr("/ndn/alice"))
	bob := tu.NoErr(enc.NameFromStr("/ndn/bob"))
	carol := tu.NoErr(enc.NameFromStr("/ndn/carol"))

	m := NewSvMap[uint64](0)
	m.Set(alice.TlvStr(), 100, 5)
	m.Set(bob.TlvStr(), 150, 3)
	m.Set(carol.TlvStr(), 150, 7)

	// Threshold large enough for sender + one peer.
	full := &spec_svs.SvsData{
		MemberSetHash: ComputeMembershipHash(m),
		VectorType:    optional.Some(spec_svs.VectorTypeFull),
		StateVector:   m.Encode(func(s uint64) uint64 { return s }),
	}
	threshold := len(full.Encode().Join()) - 1

	partial := encodePartialStateVector(m, PartialEncodeOpts{
		Sender:    carol,
		Threshold: threshold,
		Mtime: map[string]time.Time{
			alice.TlvStr(): time.Unix(10, 0),
			bob.TlvStr():   time.Unix(20, 0),
		},
	})

	require.NotEmpty(t, partial.Entries)
	require.Equal(t, carol, partial.Entries[0].Name)
	if len(partial.Entries) > 2 {
		require.Less(t, partial.Entries[1].Name.Compare(partial.Entries[2].Name), 0)
	}
}

func TestBuildSvsDataForSendPublicationPartial(t *testing.T) {
	tu.SetT(t)

	alice := tu.NoErr(enc.NameFromStr("/ndn/alice"))
	m := NewSvMap[uint64](0)
	m.Set(alice.TlvStr(), 100, 5)
	for i := range 20 {
		name := tu.NoErr(enc.NameFromStr(fmt.Sprintf("/ndn/peer%d", i)))
		m.Set(name.TlvStr(), 150, uint64(i+1))
	}

	full := &spec_svs.SvsData{
		MemberSetHash: ComputeMembershipHash(m),
		VectorType:    optional.Some(spec_svs.VectorTypeFull),
		StateVector:   m.Encode(func(s uint64) uint64 { return s }),
	}
	threshold := len(full.Encode().Join()) / 2

	pub := buildSvsDataForSend(svsSendInput{
		State: m, Reason: syncSendPublication, Threshold: threshold, Sender: alice,
	})
	vt, ok := pub.VectorType.Get()
	require.True(t, ok)
	require.Equal(t, spec_svs.VectorTypePartial, vt)
	require.Less(t, len(pub.StateVector.Entries), len(full.StateVector.Entries))

	periodic := buildSvsDataForSend(svsSendInput{
		State: m, Reason: syncSendPeriodic, Threshold: threshold, Sender: alice,
	})
	vt, ok = periodic.VectorType.Get()
	require.True(t, ok)
	require.Equal(t, spec_svs.VectorTypeFull, vt)
}

func TestOnReceivePartialMergesPresentEntriesOnly(t *testing.T) {
	tu.SetT(t)

	var updates []SvSyncUpdate
	s := &SvSync{
		o: SvSyncOpts{
			OnUpdate:        func(u SvSyncUpdate) { updates = append(updates, u) },
			PeriodicTimeout: 30 * time.Second,
		},
		state:  NewSvMap[uint64](0),
		mtime:  make(map[string]time.Time),
		ticker: time.NewTicker(30 * time.Second),
	}

	alice := tu.NoErr(enc.NameFromStr("/ndn/alice"))
	bob := tu.NoErr(enc.NameFromStr("/ndn/bob"))
	s.state.Set(alice.TlvStr(), 100, 1)
	s.state.Set(bob.TlvStr(), 150, 1)

	bobOnly := NewSvMap[uint64](0)
	bobOnly.Set(bob.TlvStr(), 150, 4)
	partialSv := bobOnly.Encode(func(s uint64) uint64 { return s })

	s.onReceiveStateVector(svSyncRecvSvArgs{
		sv:         partialSv,
		vectorType: optional.Some(spec_svs.VectorTypePartial),
		mhash:      ComputeMembershipHash(bobOnly),
	})

	require.Len(t, updates, 1)
	require.Equal(t, bob, updates[0].Name)
	require.EqualValues(t, 4, updates[0].High)
	require.EqualValues(t, 1, s.state.Get(alice.TlvStr(), 100))
	require.EqualValues(t, 4, s.state.Get(bob.TlvStr(), 150))
}

// --- mhash tests ---

func TestComputeMembershipHashStable(t *testing.T) {
	tu.SetT(t)

	m := NewSvMap[uint64](0)
	m.Set(tu.NoErr(enc.NameFromStr("/ndn/alice")).TlvStr(), 100, 1)
	m.Set(tu.NoErr(enc.NameFromStr("/ndn/bob")).TlvStr(), 150, 3)

	h1 := ComputeMembershipHash(m)
	h2 := ComputeMembershipHash(m)
	require.Equal(t, h1, h2)
	require.Len(t, h1, 32)
}

func TestComputeMembershipHashOrderIndependent(t *testing.T) {
	tu.SetT(t)

	m1 := NewSvMap[uint64](0)
	m1.Set(tu.NoErr(enc.NameFromStr("/ndn/alice")).TlvStr(), 100, 1)
	m1.Set(tu.NoErr(enc.NameFromStr("/ndn/bob")).TlvStr(), 150, 3)

	m2 := NewSvMap[uint64](0)
	m2.Set(tu.NoErr(enc.NameFromStr("/ndn/bob")).TlvStr(), 150, 3)
	m2.Set(tu.NoErr(enc.NameFromStr("/ndn/alice")).TlvStr(), 100, 1)

	require.Equal(t, ComputeMembershipHash(m1), ComputeMembershipHash(m2))
}

func TestComputeMembershipHashChangesOnMembership(t *testing.T) {
	tu.SetT(t)

	m := NewSvMap[uint64](0)
	m.Set(tu.NoErr(enc.NameFromStr("/ndn/alice")).TlvStr(), 100, 1)
	before := ComputeMembershipHash(m)

	m.Set(tu.NoErr(enc.NameFromStr("/ndn/bob")).TlvStr(), 150, 3)
	after := ComputeMembershipHash(m)
	require.NotEqual(t, before, after)
}

func TestComputeMembershipHashIgnoresSeqNo(t *testing.T) {
	tu.SetT(t)

	m1 := NewSvMap[uint64](0)
	m1.Set(tu.NoErr(enc.NameFromStr("/ndn/alice")).TlvStr(), 100, 1)

	m2 := NewSvMap[uint64](0)
	m2.Set(tu.NoErr(enc.NameFromStr("/ndn/alice")).TlvStr(), 100, 99)

	require.Equal(t, ComputeMembershipHash(m1), ComputeMembershipHash(m2))
}

func TestSvsDataInlineTLV(t *testing.T) {
	tu.SetT(t)

	m := NewSvMap[uint64](0)
	m.Set(tu.NoErr(enc.NameFromStr("/ndn/alice")).TlvStr(), 100, 1)
	sv := m.Encode(func(s uint64) uint64 { return s })

	original := &spec_svs.SvsData{
		MemberSetHash: ComputeMembershipHash(m),
		VectorType:    optional.Some(spec_svs.VectorTypeFull),
		StateVector:   sv,
	}
	wire := original.Encode().Join()

	parsed, err := spec_svs.ParseSvsData(enc.NewBufferView(wire), false)
	require.NoError(t, err)
	require.Equal(t, original.MemberSetHash, parsed.MemberSetHash)
	require.Equal(t, original.VectorType, parsed.VectorType)
	require.Equal(t, original.StateVector.Entries[0].Name.String(), parsed.StateVector.Entries[0].Name.String())
}

func TestSvsDataAnnounceTLV(t *testing.T) {
	tu.SetT(t)

	ref := tu.NoErr(enc.NameFromStr("/ndn/svs/alice/100/32=sv/1"))
	mhash := make([]byte, 32)

	original := &spec_svs.SvsData{
		MemberSetHash: mhash,
		SvsDataRef:    ref,
	}
	wire := original.Encode().Join()

	parsed, err := spec_svs.ParseSvsData(enc.NewBufferView(wire), false)
	require.NoError(t, err)
	require.Equal(t, mhash, parsed.MemberSetHash)
	require.Equal(t, ref.String(), parsed.SvsDataRef.String())
	require.Nil(t, parsed.StateVector)
	require.False(t, parsed.VectorType.IsSet())
}

func TestSvsDataLegacyParse(t *testing.T) {
	tu.SetT(t)

	m := NewSvMap[uint64](0)
	m.Set(tu.NoErr(enc.NameFromStr("/ndn/alice")).TlvStr(), 100, 1)
	legacy := &spec_svs.SvsData{StateVector: m.Encode(func(s uint64) uint64 { return s })}
	wire := legacy.Encode().Join()

	parsed, err := spec_svs.ParseSvsData(enc.NewBufferView(wire), false)
	require.NoError(t, err)
	require.Nil(t, parsed.MemberSetHash)
	require.NotNil(t, parsed.StateVector)
}

// --- pull / recovery tests ---

func TestDeriveFullVectorPrefix(t *testing.T) {
	tu.SetT(t)

	syncData := tu.NoErr(enc.NameFromStr("/ndn/svs/alice/1700000000/32=svs"))
	prefix := deriveFullVectorPrefix(syncData)
	require.Equal(t, "/ndn/svs/alice/1700000000/32=sv", prefix.String())
}

func TestPullRefFromSyncDataWire(t *testing.T) {
	tu.SetT(t)

	syncDataName := tu.NoErr(enc.NameFromStr("/ndn/svs/alice/1700000000/32=svs")).
		Append(enc.NewVersionComponent(12345))
	dataWire, err := spec.Spec{}.MakeData(
		syncDataName,
		&ndn.DataConfig{ContentType: optional.Some(ndn.ContentTypeBlob)},
		enc.Wire{enc.Buffer{0x01}},
		sig.NewSha256Signer(),
	)
	require.NoError(t, err)

	ref := pullRefFromSyncDataWire(dataWire.Wire)
	require.Equal(t, "/ndn/svs/alice/1700000000/32=sv", ref.String())
}

func TestBuildAnnounceSvsData(t *testing.T) {
	tu.SetT(t)

	m := testSvMapAliceBob()
	ref := tu.NoErr(enc.NameFromStr("/ndn/svs/alice/1700000000/32=sv/999"))
	data := buildAnnounceSvsData(m, ref)

	require.Equal(t, ComputeMembershipHash(m), data.MemberSetHash)
	require.True(t, ref.Equal(data.SvsDataRef))
	require.Nil(t, data.StateVector)
	require.False(t, data.VectorType.IsSet())

	wire := data.Encode().Join()
	parsed, err := spec_svs.ParseSvsData(enc.NewBufferView(wire), false)
	require.NoError(t, err)
	require.Equal(t, data.MemberSetHash, parsed.MemberSetHash)
	require.True(t, ref.Equal(parsed.SvsDataRef))
	require.Nil(t, parsed.StateVector)
}

func TestShouldUseAnnouncePull(t *testing.T) {
	tu.SetT(t)

	m := testSvMapAliceBob()
	sv := m.Encode(func(s uint64) uint64 { return s })
	fullSize := len((&spec_svs.SvsData{
		MemberSetHash: ComputeMembershipHash(m),
		VectorType:    optional.Some(spec_svs.VectorTypeFull),
		StateVector:   sv,
	}).Encode().Join())

	require.False(t, shouldUseAnnouncePull(syncSendPublication, fullSize-1, m))
	require.False(t, shouldUseAnnouncePull(syncSendPeriodic, fullSize+1, m))
	require.True(t, shouldUseAnnouncePull(syncSendPeriodic, fullSize-1, m))
	require.True(t, shouldUseAnnouncePull(syncSendOther, fullSize-1, m))
	require.True(t, shouldUseAnnouncePull(syncSendRecovery, fullSize-1, m))
}

func TestIsTrustedSvsDataRef(t *testing.T) {
	tu.SetT(t)

	trust := tu.NoErr(enc.NameFromStr("/ndn/svs/alice/1/32=sv"))
	ref := tu.NoErr(enc.NameFromStr("/ndn/svs/alice/1/32=sv/999"))
	bad := tu.NoErr(enc.NameFromStr("/ndn/evil/32=sv/1"))

	require.True(t, isTrustedSvsDataRef(ref, trust))
	require.True(t, isTrustedSvsDataRef(trust, trust))
	require.False(t, isTrustedSvsDataRef(bad, trust))
	require.False(t, isTrustedSvsDataRef(ref, nil))
}

func TestParseFullVectorContentRejectsBadMhash(t *testing.T) {
	tu.SetT(t)

	m := testSvMapAliceBob()
	inline := &spec_svs.SvsData{
		MemberSetHash: []byte("not-a-valid-mhash-padding-000000"),
		VectorType:    optional.Some(spec_svs.VectorTypeFull),
		StateVector:   m.Encode(func(s uint64) uint64 { return s }),
	}
	wire := inline.Encode().Join()

	_, err := parseFullVectorContent(wire)
	require.Error(t, err)
}

func TestParseFullVectorContentRejectsMissingVectorType(t *testing.T) {
	tu.SetT(t)

	m := testSvMapAliceBob()
	inline := &spec_svs.SvsData{
		MemberSetHash: ComputeMembershipHash(m),
		VectorType:    optional.None[uint64](),
		StateVector:   m.Encode(func(s uint64) uint64 { return s }),
	}
	wire := inline.Encode().Join()

	_, err := parseFullVectorContent(wire)
	require.Error(t, err)
}

func TestParseFullVectorContentRejectsMissingMhash(t *testing.T) {
	tu.SetT(t)

	m := testSvMapAliceBob()
	inline := &spec_svs.SvsData{
		MemberSetHash: nil,
		VectorType:    optional.Some(spec_svs.VectorTypeFull),
		StateVector:   m.Encode(func(s uint64) uint64 { return s }),
	}
	wire := inline.Encode().Join()

	_, err := parseFullVectorContent(wire)
	require.Error(t, err)
}

func TestParseFullVectorContent(t *testing.T) {
	tu.SetT(t)

	m := testSvMapAliceBob()
	inline := &spec_svs.SvsData{
		MemberSetHash: ComputeMembershipHash(m),
		VectorType:    optional.Some(spec_svs.VectorTypeFull),
		StateVector:   m.Encode(func(s uint64) uint64 { return s }),
	}
	wire := inline.Encode().Join()

	parsed, err := parseFullVectorContent(wire)
	require.NoError(t, err)
	require.Equal(t, inline.MemberSetHash, parsed.MemberSetHash)
	require.Len(t, parsed.StateVector.Entries, 2)
}

func TestOnPulledFullVectorMergesState(t *testing.T) {
	tu.SetT(t)

	var updates []SvSyncUpdate
	s := &SvSync{
		o: SvSyncOpts{
			OnUpdate:        func(u SvSyncUpdate) { updates = append(updates, u) },
			PeriodicTimeout: 30 * time.Second,
		},
		state:  NewSvMap[uint64](0),
		mtime:  make(map[string]time.Time),
		ticker: time.NewTicker(30 * time.Second),
		recvSv: make(chan svSyncRecvSvArgs, 1),
	}

	alice := tu.NoErr(enc.NameFromStr("/ndn/alice"))
	s.state.Set(alice.TlvStr(), 100, 1)

	remote := testSvMapAliceBob()
	content := (&spec_svs.SvsData{
		MemberSetHash: ComputeMembershipHash(remote),
		VectorType:    optional.Some(spec_svs.VectorTypeFull),
		StateVector:   remote.Encode(func(s uint64) uint64 { return s }),
	}).Encode().Join()

	go func() {
		s.onPulledFullVector(content)
	}()

	s.onReceiveStateVector(<-s.recvSv)

	require.Len(t, updates, 2)
	require.EqualValues(t, 3, s.state.Get(tu.NoErr(enc.NameFromStr("/ndn/bob")).TlvStr(), 150))
	require.EqualValues(t, 5, s.state.Get(alice.TlvStr(), 100))
}

func TestEncodeSyncDataAnnounceMode(t *testing.T) {
	tu.SetT(t)

	m := testSvMapAliceBob()
	fullSize := len((&spec_svs.SvsData{
		MemberSetHash: ComputeMembershipHash(m),
		VectorType:    optional.Some(spec_svs.VectorTypeFull),
		StateVector:   m.Encode(func(s uint64) uint64 { return s }),
	}).Encode().Join())
	require.True(t, shouldUseAnnouncePull(syncSendPeriodic, fullSize-1, m))

	announce := buildAnnounceSvsData(m, tu.NoErr(enc.NameFromStr("/ndn/svs/alice/1/32=sv/2")))
	require.Nil(t, announce.StateVector)
	vt, ok := announce.VectorType.Get()
	require.False(t, ok || vt == spec_svs.VectorTypePartial)
}

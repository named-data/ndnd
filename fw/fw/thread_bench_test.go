package fw

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/named-data/ndnd/fw/defn"
	"github.com/named-data/ndnd/fw/dispatch"
	"github.com/named-data/ndnd/fw/table"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/types/optional"
)

// Benchmarks for the forwarding pipeline of a single forwarding thread.
// Packets are decoded from pre-encoded wires on every iteration, as the
// link service would do, and passed directly to the thread pipelines.
//
// Run with:
//   go test ./fw/fw/ -run '^$' -bench . -benchmem -count 10

const benchNames = 8192 // more than the default CS capacity, so no CS hits

// benchFace is a no-op face that records the PIT token of the last packet.
type benchFace struct {
	id        uint64
	lastToken []byte
	nSent     int
}

func (f *benchFace) String() string               { return fmt.Sprintf("bench-face-%d", f.id) }
func (f *benchFace) SetFaceID(id uint64)          { f.id = id }
func (f *benchFace) FaceID() uint64               { return f.id }
func (f *benchFace) LocalURI() *defn.URI          { return nil }
func (f *benchFace) RemoteURI() *defn.URI         { return nil }
func (f *benchFace) Scope() defn.Scope            { return defn.NonLocal }
func (f *benchFace) LinkType() defn.LinkType      { return defn.PointToPoint }
func (f *benchFace) MTU() int                     { return 8800 }
func (f *benchFace) State() defn.State            { return defn.Up }
func (f *benchFace) SendPacket(o dispatch.OutPkt) { f.lastToken = o.PitToken; f.nSent++ }

type benchEnv struct {
	thread    *Thread
	consumer  *benchFace
	producer  *benchFace
	interests []enc.Wire
	data      []enc.Wire
	iter      int
}

var benchInitOnce sync.Once
var benchEnvCount atomic.Uint64

func benchInit() {
	benchInitOnce.Do(func() {
		table.Initialize()

		// Some unrelated routes so the FIB is not trivially small
		for i := range 32 {
			name, _ := enc.NameFromStr(fmt.Sprintf("/filler%d/a/b", i))
			table.FibStrategyTable.InsertNextHopEnc(name, 1, 10)
		}
	})
}

// newBenchEnv creates a forwarding thread with its own consumer and producer
// faces and a FIB route to the producer for a unique prefix.
func newBenchEnv(b *testing.B) *benchEnv {
	benchInit()

	id := benchEnvCount.Add(1)
	env := &benchEnv{
		thread:   NewThread(int(id)),
		consumer: &benchFace{id: 1000 + 2*id},
		producer: &benchFace{id: 1001 + 2*id},
	}
	dispatch.AddFace(env.consumer.id, env.consumer)
	dispatch.AddFace(env.producer.id, env.producer)

	prefix, _ := enc.NameFromStr(fmt.Sprintf("/bench/g%d", id))
	table.FibStrategyTable.InsertNextHopEnc(prefix, env.producer.id, 10)

	signer := signer.NewSha256Signer()
	content := enc.Wire{make([]byte, 1000)}
	for i := range benchNames {
		name := prefix.
			Append(enc.NewGenericComponent("app")).
			Append(enc.NewGenericComponent("stream")).
			Append(enc.NewVersionComponent(1)).
			Append(enc.NewSegmentComponent(uint64(i)))

		interest, err := spec.Spec{}.MakeInterest(name, &ndn.InterestConfig{
			Lifetime: optional.Some(4 * time.Second),
			Nonce:    optional.Some(uint32(0)),
		}, nil, nil)
		if err != nil {
			b.Fatal(err)
		}
		env.interests = append(env.interests, enc.Wire{interest.Wire.Join()})

		data, err := spec.Spec{}.MakeData(name, &ndn.DataConfig{
			Freshness: optional.Some(10 * time.Second),
		}, content, signer)
		if err != nil {
			b.Fatal(err)
		}
		env.data = append(env.data, enc.Wire{data.Wire.Join()})
	}

	return env
}

func benchParse(b *testing.B, wire enc.Wire, face uint64) *defn.Pkt {
	l3, err := defn.ParseFwPacket(enc.NewWireView(wire), false)
	if err != nil {
		b.Fatal(err)
	}
	pkt := &defn.Pkt{L3: l3, Raw: wire, IncomingFaceID: face}
	if l3.Interest != nil {
		pkt.Name = l3.Interest.NameV
	} else {
		pkt.Name = l3.Data.NameV
	}
	return pkt
}

// housekeeping emulates the periodic timers of Thread.Run.
func (env *benchEnv) housekeeping() {
	if env.iter%1024 == 0 {
		env.thread.pitCS.Update()
		env.thread.deadNonceList.RemoveExpiredEntries()
	}
}

// interestData forwards one Interest upstream and the matching Data back.
func (env *benchEnv) interestData(b *testing.B) {
	env.iter++
	k := env.iter % benchNames

	ipkt := benchParse(b, env.interests[k], env.consumer.id)
	ipkt.L3.Interest.NonceV = optional.Some(uint32(env.iter))
	env.producer.lastToken = nil
	env.thread.processIncomingInterest(ipkt)
	if env.producer.lastToken == nil {
		b.Fatal("Interest was not forwarded")
	}

	dpkt := benchParse(b, env.data[k], env.producer.id)
	dpkt.PitToken = env.producer.lastToken
	sent := env.consumer.nSent
	env.thread.processIncomingData(dpkt)
	if env.consumer.nSent != sent+1 {
		b.Fatal("Data was not forwarded")
	}

	env.housekeeping()
}

// BenchmarkFwInterestData measures an Interest forwarded to the producer
// followed by the Data returned to the consumer (CS miss).
func BenchmarkFwInterestData(b *testing.B) {
	env := newBenchEnv(b)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		env.interestData(b)
	}
}

// BenchmarkFwInterestDataParallel runs one forwarding thread per CPU,
// all sharing the global FIB as in the real forwarder.
func BenchmarkFwInterestDataParallel(b *testing.B) {
	var envs []*benchEnv
	var next atomic.Int64
	for range runtime.GOMAXPROCS(0) {
		envs = append(envs, newBenchEnv(b))
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		env := envs[next.Add(1)-1]
		for pb.Next() {
			env.interestData(b)
		}
	})
}

// BenchmarkFwCsHit measures an Interest satisfied from the Content Store.
func BenchmarkFwCsHit(b *testing.B) {
	env := newBenchEnv(b)

	// Fill the CS with a small working set
	const hot = 256
	for range hot {
		env.interestData(b)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		k := 1 + i%hot
		ipkt := benchParse(b, env.interests[k], env.consumer.id)
		ipkt.L3.Interest.NonceV = optional.Some(uint32(benchNames + i))
		sent := env.consumer.nSent
		env.thread.processIncomingInterest(ipkt)
		if env.consumer.nSent != sent+1 {
			b.Fatal("Interest was forwarded instead of CS hit")
		}
		env.iter++
		env.housekeeping()
	}
}

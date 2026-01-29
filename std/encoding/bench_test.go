package encoding_test

import (
	"crypto/rand"
	"testing"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/types/optional"
	tu "github.com/named-data/ndnd/std/utils/testutils"
)

// (AI GENERATED DESCRIPTION): Generates a slice of unsigned Data packets with random names of the specified size, random payloads of the specified byte length, and preset MetaInfo plus placeholder Ed25519 signature metadata.
func encodeDataCases(count int, payloadSize int, nameSize int) (ret []*spec.Data) {
	keyName := tu.NoErrB(enc.NameFromStr("/go-ndn/bench/signer/KEY"))

	ret = make([]*spec.Data, count)
	for i := 0; i < count; i++ {
		ret[i] = &spec.Data{
			NameV:    randomNames(1, nameSize)[0],
			ContentV: enc.Wire{make([]byte, payloadSize)},
			MetaInfo: &spec.MetaInfo{
				ContentType:     optional.Some(uint64(ndn.ContentTypeBlob)),
				FreshnessPeriod: optional.Some(4000 * time.Millisecond),
			},
			SignatureInfo: &spec.SignatureInfo{
				SignatureType: uint64(ndn.SignatureEd25519),
				KeyLocator:    &spec.KeyLocator{Name: keyName},
			},
		}
		rand.Read(ret[i].ContentV[0])
	}
	return ret
}

// (AI GENERATED DESCRIPTION): Encodes a Data packet with the provided `spec.Data`, initializing a 32‑byte placeholder for the signature field and returning the resulting wire representation.
func encodeData(data *spec.Data) enc.Wire {
	packet := &spec.Packet{Data: data}
	encoder := spec.PacketEncoder{
		Data_encoder: spec.DataEncoder{
			SignatureValue_estLen: 32,
		},
	}
	encoder.Init(packet)
	wire := encoder.Encode(packet)

	wire[encoder.Data_encoder.SignatureValue_wireIdx] = make([]byte, 32)
	return wire
}

// (AI GENERATED DESCRIPTION): Benchmarks the performance of encoding Data packets generated with the specified payload and name sizes.
func encodeDataBench(b *testing.B, payloadSize, nameSize int) {
	count := b.N
	data := encodeDataCases(count, payloadSize, nameSize)

	b.ResetTimer()
	for i := 0; i < count; i++ {
		encodeData(data[i])
	}
}

// (AI GENERATED DESCRIPTION): Benchmarks the encoding of a small Data packet, repeatedly encoding a packet with 100 bytes of payload and a 5‑byte signature to measure performance.
func BenchmarkDataEncodeSmall(b *testing.B) {
	encodeDataBench(b, 100, 5)
}

// (AI GENERATED DESCRIPTION): Benchmarks the encoding performance of a medium‑sized Data packet (1 000 bytes) by invoking the helper `encodeDataBench` with 10 encode repetitions per benchmark iteration.
func BenchmarkDataEncodeMedium(b *testing.B) {
	encodeDataBench(b, 1000, 10)
}

// (AI GENERATED DESCRIPTION): Benchmarks the encoding performance of a Data packet with a 1000‑component name and a 20‑byte payload.
func BenchmarkDataEncodeMediumLongName(b *testing.B) {
	encodeDataBench(b, 1000, 20)
}

// (AI GENERATED DESCRIPTION): Benchmarks the performance of encoding a Data packet with a 8 000‑byte content payload.
func BenchmarkDataEncodeLarge(b *testing.B) {
	encodeDataBench(b, 8000, 10)
}

// (AI GENERATED DESCRIPTION): Benchmarks decoding of Data packets with a specified payload and name size by pre‑encoding a batch of packets and repeatedly parsing them.
func decodeDataBench(b *testing.B, payloadSize, nameSize int) {
	count := b.N
	buffers := make([][]byte, count)

	for i, data := range encodeDataCases(count, payloadSize, nameSize) {
		buffers[i] = encodeData(data).Join()
	}

	b.ResetTimer()
	for i := 0; i < count; i++ {
		p, _, err := spec.ReadPacket(enc.NewBufferView(buffers[i]))
		if err != nil || p.Data == nil {
			b.Fatal(err)
		}
	}
}

// (AI GENERATED DESCRIPTION): Benchmarks the performance of decoding a small Data packet with a 100‑byte payload and a name of length 5.
func BenchmarkDataDecodeSmall(b *testing.B) {
	decodeDataBench(b, 100, 5)
}

// (AI GENERATED DESCRIPTION): Benchmarks decoding a medium‑sized Data packet by repeatedly decoding 1000 packets, each with 10‑byte payload, using the decodeDataBench helper.
func BenchmarkDataDecodeMedium(b *testing.B) {
	decodeDataBench(b, 1000, 10)
}

// (AI GENERATED DESCRIPTION): Benchmarks the decoding performance of a Data packet that has a medium‑sized name (with long component strings).
func BenchmarkDataDecodeMediumLongName(b *testing.B) {
	decodeDataBench(b, 1000, 20)
}

// (AI GENERATED DESCRIPTION): Benchmarks decoding of a large Data packet (payload size 8000 bytes) performed ten times per benchmark iteration.
func BenchmarkDataDecodeLarge(b *testing.B) {
	decodeDataBench(b, 8000, 10)
}

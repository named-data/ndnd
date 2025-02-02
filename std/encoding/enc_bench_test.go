package encoding_test

import (
	"crypto/rand"
	"testing"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/utils"
	tu "github.com/named-data/ndnd/std/utils/testutils"
)

func encodeDataCases(count int, payloadSize int, nameSize int) (ret []*spec.Data) {
	keyName := tu.NoErrB(enc.NameFromStr("/go-ndn/bench/signer/KEY"))

	ret = make([]*spec.Data, count)
	for i := 0; i < count; i++ {
		ret[i] = &spec.Data{
			NameV:    randomNames(1, nameSize)[0],
			ContentV: enc.Wire{make([]byte, payloadSize)},
			MetaInfo: &spec.MetaInfo{
				ContentType:     utils.IdPtr(uint64(ndn.ContentTypeBlob)),
				FreshnessPeriod: utils.IdPtr(4000 * time.Millisecond),
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

func encodeDataBench(b *testing.B, payloadSize, nameSize int) {
	count := b.N
	data := encodeDataCases(count, payloadSize, nameSize)

	b.ResetTimer()
	for i := 0; i < count; i++ {
		encodeData(data[i])
	}
}

func BenchmarkDataEncodeSmall(b *testing.B) {
	encodeDataBench(b, 100, 5)
}

func BenchmarkDataEncodeMedium(b *testing.B) {
	encodeDataBench(b, 1000, 10)
}

func BenchmarkDataEncodeMediumLongName(b *testing.B) {
	encodeDataBench(b, 1000, 20)
}

func BenchmarkDataEncodeLarge(b *testing.B) {
	encodeDataBench(b, 8000, 10)
}

func decodeDataBench(b *testing.B, payloadSize, nameSize int) {
	count := b.N
	buffers := make([][]byte, count)

	for i, data := range encodeDataCases(count, payloadSize, nameSize) {
		buffers[i] = encodeData(data).Join()
	}

	b.ResetTimer()
	for i := 0; i < count; i++ {
		p, _, err := spec.ReadPacket(enc.NewBufferReader(buffers[i]))
		if err != nil || p.Data == nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDataDecodeSmall(b *testing.B) {
	decodeDataBench(b, 100, 5)
}

func BenchmarkDataDecodeMedium(b *testing.B) {
	decodeDataBench(b, 1000, 10)
}

func BenchmarkDataDecodeMediumLongName(b *testing.B) {
	decodeDataBench(b, 1000, 20)
}

func BenchmarkDataDecodeLarge(b *testing.B) {
	decodeDataBench(b, 8000, 10)
}

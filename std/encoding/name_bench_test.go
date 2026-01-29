package encoding_test

import (
	"crypto/rand"
	"encoding/binary"
	"runtime"
	"testing"

	enc "github.com/named-data/ndnd/std/encoding"
	tu "github.com/named-data/ndnd/std/utils/testutils"
)

// (AI GENERATED DESCRIPTION): Creates a slice of `count` random `enc.Name` objects, each built from `size` components whose type IDs are randomly generated (always at least 1024) and whose byte payloads are filled with random data.
func randomNames(count int, size int) []enc.Name {
	names := make([]enc.Name, count)
	for i := 0; i < count; i++ {
		for j := 0; j < size; j++ {
			bytes := make([]byte, 12+j)
			rand.Read(bytes)
			typ := max(enc.TLNum(uint16(binary.BigEndian.Uint16(bytes[:4])-1024)), 1024)
			names[i] = append(names[i], enc.NewBytesComponent(typ, bytes[4:]))
		}
	}
	return names
}

// (AI GENERATED DESCRIPTION): Benchmarks the encoding of randomly generated names of a specified size by repeatedly calling the supplied encode function.
func benchmarkNameEncode(b *testing.B, size int, encode func(name enc.Name)) {
	runtime.GC()
	names := randomNames(b.N, size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encode(names[i])
	}
}

// (AI GENERATED DESCRIPTION): Benchmarks the performance of hashing a name composed of 20 components.
func BenchmarkNameHash(b *testing.B) {
	benchmarkNameEncode(b, 20, func(name enc.Name) { _ = name.Hash() })
}

// (AI GENERATED DESCRIPTION): Benchmarks the performance of the `PrefixHash` method on a 20‑component `enc.Name`.
func BenchmarkNameHashPrefix(b *testing.B) {
	benchmarkNameEncode(b, 20, func(name enc.Name) { _ = name.PrefixHash() })
}

// (AI GENERATED DESCRIPTION): Benchmarks the performance of generating a string representation of a 20‑component name.
func BenchmarkNameStringEncode(b *testing.B) {
	benchmarkNameEncode(b, 20, func(name enc.Name) { _ = name.String() })
}

// (AI GENERATED DESCRIPTION): Benchmarks the conversion of a `Name` into its TLV string representation, measuring the encoding performance across repeated executions.
func BenchmarkNameTlvStrEncode(b *testing.B) {
	benchmarkNameEncode(b, 20, func(name enc.Name) { _ = name.TlvStr() })
}

// (AI GENERATED DESCRIPTION): Benchmarks the performance of converting a 20‑component Name to its byte slice representation via the `Bytes()` method.
func BenchmarkNameBytesEncode(b *testing.B) {
	benchmarkNameEncode(b, 20, func(name enc.Name) { _ = name.Bytes() })
}

// (AI GENERATED DESCRIPTION): Benchmarks the performance of converting a single Name component to its string representation.
func BenchmarkNameComponentStringEncode(b *testing.B) {
	benchmarkNameEncode(b, 1, func(name enc.Name) { _ = name[0].String() })
}

// (AI GENERATED DESCRIPTION): Benchmarks the conversion of the first (and only) component of a one‑component name into its TLV string representation.
func BenchmarkNameComponentTlvStrEncode(b *testing.B) {
	benchmarkNameEncode(b, 1, func(name enc.Name) { _ = name[0].TlvStr() })
}

// (AI GENERATED DESCRIPTION): Benchmarks the performance of cloning a Name object by repeatedly cloning a 20‑component name during a benchmark run.
func BenchmarkNameClone(b *testing.B) {
	benchmarkNameEncode(b, 20, func(name enc.Name) { _ = name.Clone() })
}

// (AI GENERATED DESCRIPTION): Benchmarks the time to decode encoded names by generating random names of a given size, encoding each into type T, then repeatedly decoding them.
func benchmarkNameDecode[T any](b *testing.B, size int, encode func(name enc.Name) T, decode func(e T)) {
	names := randomNames(b.N, size)
	nameEncs := make([]T, b.N)
	for i := 0; i < b.N; i++ {
		nameEncs[i] = encode(names[i])
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decode(nameEncs[i])
	}
}

// (AI GENERATED DESCRIPTION): Benchmarks the time taken to convert an `enc.Name` to its string representation via `Name.String()` and then back into a `Name` using `NameFromStr`.
func BenchmarkNameStringDecode(b *testing.B) {
	benchmarkNameDecode(b, 20,
		func(name enc.Name) string { return name.String() },
		func(s string) { _ = tu.NoErrB(enc.NameFromStr(s)) })
}

// (AI GENERATED DESCRIPTION): Benchmarks the round‑trip conversion of a Name to its TLV string representation and back to a Name.
func BenchmarkNameTlvStrDecode(b *testing.B) {
	benchmarkNameDecode(b, 20,
		func(name enc.Name) string { return name.TlvStr() },
		func(s string) { _ = tu.NoErrB(enc.NameFromTlvStr(s)) })
}

// (AI GENERATED DESCRIPTION): Benchmarks the performance of converting a single name component to its string representation and back again.
func BenchmarkNameComponentStringDecode(b *testing.B) {
	benchmarkNameDecode(b, 1,
		func(name enc.Name) string { return name[0].String() },
		func(s string) { _ = tu.NoErrB(enc.ComponentFromStr(s)) })
}

// (AI GENERATED DESCRIPTION): Benchmarks decoding a Name component from its TLV string representation.
func BenchmarkNameComponentTlvStrDecode(b *testing.B) {
	benchmarkNameDecode(b, 1,
		func(name enc.Name) string { return name[0].TlvStr() },
		func(s string) { _ = tu.NoErrB(enc.ComponentFromTlvStr(s)) })
}

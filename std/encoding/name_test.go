package encoding_test

import (
	"encoding/hex"
	"strings"
	"testing"
	"unsafe"

	enc "github.com/named-data/ndnd/std/encoding"
	tu "github.com/named-data/ndnd/std/utils/testutils"
	"github.com/stretchr/testify/require"
)

// (AI GENERATED DESCRIPTION): Tests that `ComponentFromStr` correctly parses various string representations into `Component` structs, covering generic, percent‑encoded, version, and parameters SHA256 digest components.
func TestComponentFromStrBasic(t *testing.T) {
	tu.SetT(t)

	comp := tu.NoErr(enc.ComponentFromStr("aa"))
	require.Equal(t, enc.Component{enc.TypeGenericNameComponent, []byte("aa")}, comp)

	comp = tu.NoErr(enc.ComponentFromStr("a%20a"))
	require.Equal(t, enc.Component{enc.TypeGenericNameComponent, []byte("a a")}, comp)

	comp = tu.NoErr(enc.ComponentFromStr("v=10"))
	require.Equal(t, enc.Component{enc.TypeVersionNameComponent, []byte{0x0a}}, comp)

	comp = tu.NoErr(enc.ComponentFromStr("params-sha256=3d319b4802e56af766c0e73d2ced4f1560fba2b7"))
	require.Equal(t,
		enc.Component{enc.TypeParametersSha256DigestComponent,
			[]byte{0x3d, 0x31, 0x9b, 0x48, 0x02, 0xe5, 0x6a, 0xf7, 0x66, 0xc0, 0xe7, 0x3d,
				0x2c, 0xed, 0x4f, 0x15, 0x60, 0xfb, 0xa2, 0xb7}},
		comp)

	comp = tu.NoErr(enc.ComponentFromStr(""))
	require.Equal(t, enc.Component{enc.TypeGenericNameComponent, []byte("")}, comp)
}

// (AI GENERATED DESCRIPTION): Tests that generic name components are correctly parsed from bytes and strings, percent‑encoded, and round‑tripped back to their binary representation.
func TestGenericComponent(t *testing.T) {
	tu.SetT(t)

	var buf = []byte("\x08\x0andn-python")
	c := tu.NoErr(enc.ComponentFromBytes(buf))
	require.Equal(t, enc.Component{enc.TypeGenericNameComponent, []byte("ndn-python")}, c)
	c2 := tu.NoErr(enc.ComponentFromStr("ndn-python"))
	require.Equal(t, c, c2)
	c2 = tu.NoErr(enc.ComponentFromStr("8=ndn-python"))
	require.Equal(t, c, c2)
	require.Equal(t, buf, c.Bytes())

	buf = []byte("\x08\x07foo%bar")
	c = tu.NoErr(enc.ComponentFromBytes(buf))
	require.Equal(t, enc.Component{enc.TypeGenericNameComponent, []byte("foo%bar")}, c)
	require.Equal(t, "foo%25bar", c.String())
	c2 = tu.NoErr(enc.ComponentFromStr("foo%25bar"))
	require.Equal(t, c, c2)
	c2 = tu.NoErr(enc.ComponentFromStr("8=foo%25bar"))
	require.Equal(t, c, c2)
	require.Equal(t, buf, c.Bytes())

	buf = []byte("\x08\x04-._~")
	c = tu.NoErr(enc.ComponentFromBytes(buf))
	require.Equal(t, enc.Component{enc.TypeGenericNameComponent, []byte("-._~")}, c)
	require.Equal(t, "-._~", c.String())
	c2 = tu.NoErr(enc.ComponentFromStr("-._~"))
	require.Equal(t, c, c2)
	c2 = tu.NoErr(enc.ComponentFromStr("8=-._~"))
	require.Equal(t, c, c2)
	require.Equal(t, buf, c.Bytes())

	err := tu.Err(enc.ComponentFromStr(":/?#[]@"))
	require.IsType(t, enc.ErrFormat{}, err)
	buf = []byte(":/?#[]@")
	c = enc.Component{enc.TypeGenericNameComponent, buf}
	require.Equal(t, "%3A%2F%3F%23%5B%5D%40", c.String())
	c2 = tu.NoErr(enc.ComponentFromStr("%3A%2F%3F%23%5B%5D%40"))
	require.Equal(t, c, c2)

	err = tu.Err(enc.ComponentFromStr("/"))
	require.IsType(t, enc.ErrFormat{}, err)
	c = enc.Component{enc.TypeGenericNameComponent, []byte{}}
	require.Equal(t, "", c.String())
	require.Equal(t, c.Bytes(), []byte("\x08\x00"))
	c2 = tu.NoErr(enc.ComponentFromStr(""))
	require.Equal(t, c, c2)
}

// (AI GENERATED DESCRIPTION): Verifies that NDN component values are correctly parsed from bytes and strings, correctly converted to string representations, correctly constructed from raw components, and that invalid component strings are rejected.
func TestComponentTypes(t *testing.T) {
	tu.SetT(t)

	hexText := "28bad4b5275bd392dbb670c75cf0b66f13f7942b21e80f55c0e86b374753a548"
	value := tu.NoErr(hex.DecodeString(hexText))

	buf := make([]byte, len(value)+2)
	buf[0] = byte(enc.TypeImplicitSha256DigestComponent)
	buf[1] = 0x20
	copy(buf[2:], value)
	c := tu.NoErr(enc.ComponentFromBytes(buf))
	require.Equal(t, enc.Component{enc.TypeImplicitSha256DigestComponent, value}, c)
	require.Equal(t, "sha256digest="+hexText, c.String())
	c2 := tu.NoErr(enc.ComponentFromStr("sha256digest=" + hexText))
	require.Equal(t, c, c2)
	c2 = tu.NoErr(enc.ComponentFromStr("sha256digest=" + strings.ToUpper(hexText)))
	require.Equal(t, c, c2)

	buf = make([]byte, len(value)+2)
	buf[0] = byte(enc.TypeParametersSha256DigestComponent)
	buf[1] = 0x20
	copy(buf[2:], value)
	c = tu.NoErr(enc.ComponentFromBytes(buf))
	require.Equal(t, enc.Component{enc.TypeParametersSha256DigestComponent, value}, c)
	require.Equal(t, "params-sha256="+hexText, c.String())
	c2 = tu.NoErr(enc.ComponentFromStr("params-sha256=" + hexText))
	require.Equal(t, c, c2)
	c2 = tu.NoErr(enc.ComponentFromStr("params-sha256=" + strings.ToUpper(hexText)))
	require.Equal(t, c, c2)

	c = tu.NoErr(enc.ComponentFromBytes([]byte{0x09, 0x03, '9', 0x3d, 'A'}))
	require.Equal(t, "9=9%3DA", c.String())
	require.Equal(t, 9, int(c.Typ))
	c2 = tu.NoErr(enc.ComponentFromStr("9=9%3DA"))
	require.Equal(t, c, c2)

	c = tu.NoErr(enc.ComponentFromBytes([]byte{0xfd, 0xff, 0xff, 0x00}))
	require.Equal(t, "65535=", c.String())
	require.Equal(t, 0xffff, int(c.Typ))
	c2 = tu.NoErr(enc.ComponentFromStr("65535="))
	require.Equal(t, c, c2)

	c = tu.NoErr(enc.ComponentFromBytes([]byte{0xfd, 0x57, 0x65, 0x01, 0x2e}))
	require.Equal(t, "22373=.", c.String())
	require.Equal(t, 0x5765, int(c.Typ))
	c2 = tu.NoErr(enc.ComponentFromStr("22373=%2e"))
	require.Equal(t, c, c2)

	tu.Err(enc.ComponentFromStr("0=A"))
	tu.Err(enc.ComponentFromStr("-1=A"))
	tu.Err(enc.ComponentFromStr("+=A"))
	tu.Err(enc.ComponentFromStr("1=2=A"))
	tu.Err(enc.ComponentFromStr("==A"))
	tu.Err(enc.ComponentFromStr("%%"))
	tu.Err(enc.ComponentFromStr("ABCD%EF%0"))
	tu.Err(enc.ComponentFromStr("ABCD%GH"))
	tu.Err(enc.ComponentFromStr("sha256digest=a04z"))
	tu.Err(enc.ComponentFromStr("65536=a04z"))

	require.Equal(t, []byte("\x32\x01\r"), enc.NewSegmentComponent(13).Bytes())
	require.Equal(t, []byte("\x34\x01\r"), enc.NewByteOffsetComponent(13).Bytes())
	require.Equal(t, []byte("\x3a\x01\r"), enc.NewSequenceNumComponent(13).Bytes())
	require.Equal(t, []byte("\x36\x01\r"), enc.NewVersionComponent(13).Bytes())
	tm := uint64(15686790223318112)
	require.Equal(t, []byte("\x38\x08\x00\x37\xbb\x0d\x76\xed\x4c\x60"), enc.NewTimestampComponent(tm).Bytes())
}

// (AI GENERATED DESCRIPTION): Verifies that the Component type’s Compare and Equal methods correctly order and compare components of varying types and byte values.
func TestComponentCompare(t *testing.T) {
	tu.SetT(t)

	comps := []enc.Component{
		{1, tu.NoErr(hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000"))},
		{1, tu.NoErr(hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001"))},
		{1, tu.NoErr(hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"))},
		{2, tu.NoErr(hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000"))},
		{2, tu.NoErr(hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001"))},
		{2, tu.NoErr(hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"))},
		{3, []byte{}},
		{3, []byte{0x44}},
		{3, []byte{0x46}},
		{3, []byte{0x41, 0x41}},
		tu.NoErr(enc.ComponentFromStr("")),
		tu.NoErr(enc.ComponentFromStr("D")),
		tu.NoErr(enc.ComponentFromStr("F")),
		tu.NoErr(enc.ComponentFromStr("AA")),
		tu.NoErr(enc.ComponentFromStr("21426=")),
		tu.NoErr(enc.ComponentFromStr("21426=%44")),
		tu.NoErr(enc.ComponentFromStr("21426=%46")),
		tu.NoErr(enc.ComponentFromStr("21426=%41%41")),
	}

	for i := 0; i < len(comps); i++ {
		for j := 0; j < len(comps); j++ {
			require.Equal(t, i == j, comps[i].Equal(comps[j]))
			if i < j {
				require.Equal(t, -1, comps[i].Compare(comps[j]))
			} else if i == j {
				require.Equal(t, 0, comps[i].Compare(comps[j]))
			} else {
				require.Equal(t, 1, comps[i].Compare(comps[j]))
			}
		}
	}
}

// (AI GENERATED DESCRIPTION): TestNameBasic validates that a complex name string containing generic components and an implicit SHA‑256 digest component is parsed into a Name structure with the correct component types and values, and that the resulting name’s encoding length and byte representation match the expected values.
func TestNameBasic(t *testing.T) {
	tu.SetT(t)

	uri := "/Emid/25042=P3//./%1C%9F/sha256digest=0415e3624a151850ac686c84f155f29808c0dd73819aa4a4c20be73a4d8a874c"
	name := tu.NoErr(enc.NameFromStr(uri))
	require.Equal(t, 6, len(name))
	require.Equal(t, tu.NoErr(enc.ComponentFromStr("Emid")), name[0])
	require.Equal(t, tu.NoErr(enc.ComponentFromBytes([]byte("\xfd\x61\xd2\x02\x50\x33"))), name[1])
	require.Equal(t, enc.Component{enc.TypeGenericNameComponent, []byte{}}, name[2])
	require.Equal(t, enc.Component{enc.TypeGenericNameComponent, []byte{'.'}}, name[3])
	require.Equal(t, enc.Component{enc.TypeGenericNameComponent, []byte{'\x1c', '\x9f'}}, name[4])
	require.Equal(t, enc.TypeImplicitSha256DigestComponent, name[5].Typ)

	require.Equal(t, 57-2, name.EncodingLength())
	b := []byte("\x07\x37\x08\x04Emid\xfda\xd2\x02P3\x08\x00\x08\x01.\x08\x02\x1c\x9f" +
		"\x01 \x04\x15\xe3bJ\x15\x18P\xachl\x84\xf1U\xf2\x98\x08\xc0\xdds\x81" +
		"\x9a\xa4\xa4\xc2\x0b\xe7:M\x8a\x87L")
	require.Equal(t, b, name.Bytes())
}

// (AI GENERATED DESCRIPTION): Tests that `NameFromStr` correctly parses input strings into `Name` objects and that the resulting `String()` method outputs the canonical representation, including proper handling of slashes, whitespace, and percent‑encoding.
func TestNameString(t *testing.T) {
	tu.SetT(t)

	tester := func(sIn, sOut string) {
		require.Equal(t, sOut, tu.NoErr(enc.NameFromStr(sIn)).String())
	}

	tester("/hello/world", "/hello/world")
	tester("hello/world", "/hello/world")
	tester("hello/world/", "/hello/world")
	tester("/hello/world/", "/hello/world")
	tester("/hello/world/  ", "/hello/world/%20%20")
	tester("/:?#[]@", "/%3A%3F%23%5B%5D%40")
	tester(" hello\t/\tworld \r\n", "/%20hello%09/%09world%20%0D%0A")

	tester("", "/")
	tester("/", "/")
	tester(" ", "/%20")
	tester("/hello//world", "/hello//world")
	tester("/hello/./world", "/hello/./world")
	tester("/hello/../world", "/hello/../world")
	tester("//", "//")
}

// (AI GENERATED DESCRIPTION): Verifies that the Name type’s Equal and Compare methods correctly determine equality and lexicographic order for a set of example names.
func TestNameCompare(t *testing.T) {
	tu.SetT(t)

	strs := []string{
		"/",
		"/sha256digest=0000000000000000000000000000000000000000000000000000000000000000",
		"/sha256digest=0000000000000000000000000000000000000000000000000000000000000001",
		"/sha256digest=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
		"/params-sha256=0000000000000000000000000000000000000000000000000000000000000000",
		"/params-sha256=0000000000000000000000000000000000000000000000000000000000000001",
		"/params-sha256=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
		"/3=",
		"/3=D",
		"/3=F",
		"/3=AA",
		"//",
		"/D",
		"/D/sha256digest=0000000000000000000000000000000000000000000000000000000000000000",
		"/D/sha256digest=0000000000000000000000000000000000000000000000000000000000000001",
		"/D/sha256digest=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
		"/D/params-sha256=0000000000000000000000000000000000000000000000000000000000000000",
		"/D/params-sha256=0000000000000000000000000000000000000000000000000000000000000001",
		"/D/params-sha256=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
		"/D/3=",
		"/D/3=D",
		"/D/3=F",
		"/D/3=AA",
		"/D//",
		"/D/D",
		"/D/F",
		"/D/AA",
		"/D/21426=/",
		"/D/21426=D",
		"/D/21426=F",
		"/D/21426=AA",
		"/F",
		"/AA",
		"/21426=",
		"/21426=D",
		"/21426=F",
		"/21426=AA",
	}
	names := make([]enc.Name, len(strs))
	for i, s := range strs {
		names[i] = tu.NoErr(enc.NameFromStr(s))
	}
	for i := 0; i < len(names); i++ {
		for j := 0; j < len(names); j++ {
			require.Equal(t, i == j, names[i].Equal(names[j]))
			if i < j {
				require.Equal(t, -1, names[i].Compare(names[j]))
			} else if i == j {
				require.Equal(t, 0, names[i].Compare(names[j]))
			} else {
				require.Equal(t, 1, names[i].Compare(names[j]))
			}
		}
	}
}

// (AI GENERATED DESCRIPTION): TestNameIsPrefix verifies that the Name.IsPrefix method correctly identifies when one NDN name is a prefix of another, checking identical names, root prefixes, child prefixes, and non‑matching cases.
func TestNameIsPrefix(t *testing.T) {
	tu.SetT(t)

	testTrue := func(s1, s2 string) {
		n1 := tu.NoErr(enc.NameFromStr(s1))
		n2 := tu.NoErr(enc.NameFromStr(s2))
		require.True(t, n1.IsPrefix(n2))
	}
	testFalse := func(s1, s2 string) {
		n1 := tu.NoErr(enc.NameFromStr(s1))
		n2 := tu.NoErr(enc.NameFromStr(s2))
		require.False(t, n1.IsPrefix(n2))
	}

	testTrue("/", "/")
	testTrue("/", "3=D")
	testTrue("/", "/F")
	testTrue("/", "/21426=AA")

	testTrue("/B", "/B")
	testTrue("/B", "/B/3=D")
	testTrue("/B", "/B/F")
	testTrue("/B", "/B/21426=AA")

	testFalse("/C", "/")
	testFalse("/C", "3=D")
	testFalse("/C", "/F")
	testFalse("/C", "/21426=AA")
}

// (AI GENERATED DESCRIPTION): Converts an NDN name to its canonical wire‑format byte representation.
func TestNameBytes(t *testing.T) {
	tu.SetT(t)

	n := tu.NoErr(enc.NameFromStr("/a/b/c/d"))
	require.Equal(t, []byte("\x07\x0c\x08\x01a\x08\x01b\x08\x01c\x08\x01d"), n.Bytes())
	require.Equal(t, []byte("\x07\x00"), enc.Name{}.Bytes())

	n2 := tu.NoErr(enc.NameFromBytes([]byte("\x07\x0c\x08\x01a\x08\x01b\x08\x01c\x08\x01d")))
	require.True(t, n.Equal(n2))
}

// (AI GENERATED DESCRIPTION): Tests that appending components to a Name correctly allocates new underlying arrays (avoiding aliasing) and verifies that chained appends reuse buffers only when safe.
func TestNameAppend(t *testing.T) {
	tu.SetT(t)

	// This section illustrates the issue with using append()
	// If we have a prefix which has an underlying array larger than the slice itself,
	// then subsequent appends will modify the same array. This will overwrite any
	// names created from the same prefix.
	prefix := tu.NoErr(enc.NameFromStr("/a/b/c/z/z/z"))[:3]
	name1 := append(prefix, tu.NoErr(enc.NameFromStr("d1/e1/f1"))...)
	name2 := append(prefix, tu.NoErr(enc.NameFromStr("d2/e2/f2"))...)
	require.Equal(t, name1.String(), name2.String()) // should not be equal

	// This section illustrates the correct way to append names
	// The Append function allocates a new array for the new name
	name3 := prefix.Append(tu.NoErr(enc.NameFromStr("d3/e3/f3"))...)
	name4 := prefix.Append(tu.NoErr(enc.NameFromStr("d4/e4/f4"))...)

	// Appends can be chained
	name5 := prefix.
		Append(enc.NewGenericComponent("d5")).
		Append(enc.NewGenericComponent("e5")).
		Append(enc.NewGenericComponent("f5"))
	name6 := name5.
		Append(enc.NewGenericComponent("g6")).
		Append(enc.NewGenericComponent("h6"))
	name7 := name5.
		Append(enc.NewGenericComponent("g7")).
		Append(enc.NewGenericComponent("h7"))

	// Append will allocate a new array when the underlying
	// array is too small to hold the new name
	prefix2 := tu.NoErr(enc.NameFromStr("/a/b/c"))
	name8 := prefix2.
		Append(enc.NewGenericComponent("d8")).
		Append(enc.NewGenericComponent("e8"))

	// This will not allocate a new array as name8 should
	// have enough space for the new components.
	name9 := name8.
		Append(enc.NewGenericComponent("f9")).
		Append(enc.NewGenericComponent("g9"))

	// This will allocate on the same array as name9 as long as
	// possible, but will make a new array because space runs out
	name10 := name9.
		Append(enc.NewGenericComponent("h10")).
		Append(enc.NewGenericComponent("i10")).
		Append(enc.NewGenericComponent("j10")).
		Append(enc.NewGenericComponent("k10")).
		Append(enc.NewGenericComponent("l10")).
		Append(enc.NewGenericComponent("m10")).
		Append(enc.NewGenericComponent("n10"))

	require.Equal(t, "/a/b/c/d3/e3/f3", name3.String())
	require.Equal(t, "/a/b/c/d4/e4/f4", name4.String())
	require.Equal(t, "/a/b/c/d5/e5/f5", name5.String())
	require.Equal(t, "/a/b/c/d5/e5/f5/g6/h6", name6.String())
	require.Equal(t, "/a/b/c/d5/e5/f5/g7/h7", name7.String())
	require.Equal(t, "/a/b/c/d8/e8", name8.String())
	require.Equal(t, "/a/b/c/d8/e8/f9/g9", name9.String())
	require.Equal(t, "/a/b/c/d8/e8/f9/g9/h10/i10/j10/k10/l10/m10/n10", name10.String())

	// When appends are chained, a new array should be allocated only once
	require.True(t, unsafe.SliceData(prefix) != unsafe.SliceData(name3))
	require.True(t, unsafe.SliceData(prefix) != unsafe.SliceData(name5))
	require.True(t, unsafe.SliceData(name5) == unsafe.SliceData(name6)) // no malloc
	require.True(t, unsafe.SliceData(name5) != unsafe.SliceData(name7)) // second append
	require.True(t, unsafe.SliceData(prefix2) != unsafe.SliceData(name8))
	require.True(t, unsafe.SliceData(name8) == unsafe.SliceData(name9))
	require.True(t, unsafe.SliceData(name9) != unsafe.SliceData(name10))
}

// (AI GENERATED DESCRIPTION): Tests that `Name.At` correctly retrieves the component at a given positive or negative index and returns an empty component when the index is out of bounds.
func TestNameAt(t *testing.T) {
	tu.SetT(t)

	n := tu.NoErr(enc.NameFromStr("/a/b/c/d"))
	require.Equal(t, "a", n.At(0).String())
	require.Equal(t, "b", n.At(1).String())
	require.Equal(t, "c", n.At(2).String())
	require.Equal(t, "d", n.At(3).String())
	require.Equal(t, enc.Component{}, n.At(4))
	require.Equal(t, "d", n.At(-1).String())
	require.Equal(t, "c", n.At(-2).String())
	require.Equal(t, "b", n.At(-3).String())
	require.Equal(t, "a", n.At(-4).String())
	require.Equal(t, enc.Component{}, n.At(-5))
}

// (AI GENERATED DESCRIPTION): Returns a prefix of the name based on the given index—positive values select the first N components, negative values drop N components from the end, and out‑of‑range indices are clamped to the root or full name.
func TestNamePrefix(t *testing.T) {
	tu.SetT(t)

	n := tu.NoErr(enc.NameFromStr("/a/b/c/d"))
	require.Equal(t, "/", n.Prefix(0).String())
	require.Equal(t, "/a", n.Prefix(1).String())
	require.Equal(t, "/a/b", n.Prefix(2).String())
	require.Equal(t, "/a/b/c", n.Prefix(3).String())
	require.Equal(t, "/a/b/c/d", n.Prefix(4).String())
	require.Equal(t, "/a/b/c/d", n.Prefix(5).String())
	require.Equal(t, "/a/b/c", n.Prefix(-1).String())
	require.Equal(t, "/a/b", n.Prefix(-2).String())
	require.Equal(t, "/a", n.Prefix(-3).String())
	require.Equal(t, "/", n.Prefix(-4).String())
	require.Equal(t, "/", n.Prefix(-5).String())
}

// (AI GENERATED DESCRIPTION): Test that converting a name component and an entire name to a TLV string and back preserves the original values.
func TestNameTlvStr(t *testing.T) {
	tu.SetT(t)
	for _, name := range randomNames(1000, 20) {
		comp2 := tu.NoErr(enc.ComponentFromTlvStr(name[10].TlvStr()))
		require.Equal(t, name[10], comp2)
		name2 := tu.NoErr(enc.NameFromTlvStr(name.TlvStr()))
		require.Equal(t, name, name2)
	}
}

// (AI GENERATED DESCRIPTION): Creates a deep copy of a `Name`, producing an equal but independent instance whose component slices are allocated separately.
func TestNameClone(t *testing.T) {
	tu.SetT(t)
	n := tu.NoErr(enc.NameFromStr("/a/b/c/d"))
	n2 := n.Clone()
	require.Equal(t, n, n2)
	require.True(t, unsafe.SliceData(n) != unsafe.SliceData(n2))
	require.True(t, unsafe.SliceData(n[0].Val) != unsafe.SliceData(n2[0].Val))
}

// (AI GENERATED DESCRIPTION): Tests that a sample Name’s Hash, PrefixHash and component Hash methods return the expected hash values.
func TestNameHash(t *testing.T) {
	tu.SetT(t)

	// Just test if it panics / behavior changes
	n := tu.NoErr(enc.NameFromStr("/a/b/c/d"))
	require.Equal(t, uint64(0xa9893a09c0db96c8), n.Hash())
	require.Equal(t, []uint64{
		0xef46db3751d8e999, 0x4c0fd87ef6387cbc,
		0xcbf6b2420b268cbf, 0xd853f58cf3654027,
		0xa9893a09c0db96c8,
	}, n.PrefixHash())
	require.Equal(t, uint64(0x4c0fd87ef6387cbc), n[0].Hash())
}

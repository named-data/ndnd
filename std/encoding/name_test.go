package encoding_test

import (
	"encoding/hex"
	"strings"
	"testing"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/utils"
	"github.com/stretchr/testify/require"
)

func TestComponentFromStrBasic(t *testing.T) {
	utils.SetTestingT(t)

	comp := utils.WithoutErr(enc.ComponentFromStr("aa"))
	require.Equal(t, enc.Component{enc.TypeGenericNameComponent, []byte("aa")}, comp)

	comp = utils.WithoutErr(enc.ComponentFromStr("a%20a"))
	require.Equal(t, enc.Component{enc.TypeGenericNameComponent, []byte("a a")}, comp)

	comp = utils.WithoutErr(enc.ComponentFromStr("v=10"))
	require.Equal(t, enc.Component{enc.TypeVersionNameComponent, []byte{0x0a}}, comp)

	comp = utils.WithoutErr(enc.ComponentFromStr("params-sha256=3d319b4802e56af766c0e73d2ced4f1560fba2b7"))
	require.Equal(t,
		enc.Component{enc.TypeParametersSha256DigestComponent,
			[]byte{0x3d, 0x31, 0x9b, 0x48, 0x02, 0xe5, 0x6a, 0xf7, 0x66, 0xc0, 0xe7, 0x3d,
				0x2c, 0xed, 0x4f, 0x15, 0x60, 0xfb, 0xa2, 0xb7}},
		comp)

	comp = utils.WithoutErr(enc.ComponentFromStr(""))
	require.Equal(t, enc.Component{enc.TypeGenericNameComponent, []byte("")}, comp)
}

func TestGenericComponent(t *testing.T) {
	utils.SetTestingT(t)

	var buf = []byte("\x08\x0andn-python")
	c := utils.WithoutErr(enc.ComponentFromBytes(buf))
	require.Equal(t, enc.Component{enc.TypeGenericNameComponent, []byte("ndn-python")}, c)
	c2 := utils.WithoutErr(enc.ComponentFromStr("ndn-python"))
	require.Equal(t, c, c2)
	c2 = utils.WithoutErr(enc.ComponentFromStr("8=ndn-python"))
	require.Equal(t, c, c2)
	require.Equal(t, buf, c.Bytes())

	buf = []byte("\x08\x07foo%bar")
	c = utils.WithoutErr(enc.ComponentFromBytes(buf))
	require.Equal(t, enc.Component{enc.TypeGenericNameComponent, []byte("foo%bar")}, c)
	require.Equal(t, "foo%25bar", c.String())
	c2 = utils.WithoutErr(enc.ComponentFromStr("foo%25bar"))
	require.Equal(t, c, c2)
	c2 = utils.WithoutErr(enc.ComponentFromStr("8=foo%25bar"))
	require.Equal(t, c, c2)
	require.Equal(t, buf, c.Bytes())

	buf = []byte("\x08\x04-._~")
	c = utils.WithoutErr(enc.ComponentFromBytes(buf))
	require.Equal(t, enc.Component{enc.TypeGenericNameComponent, []byte("-._~")}, c)
	require.Equal(t, "-._~", c.String())
	c2 = utils.WithoutErr(enc.ComponentFromStr("-._~"))
	require.Equal(t, c, c2)
	c2 = utils.WithoutErr(enc.ComponentFromStr("8=-._~"))
	require.Equal(t, c, c2)
	require.Equal(t, buf, c.Bytes())

	err := utils.WithErr(enc.ComponentFromStr(":/?#[]@"))
	require.IsType(t, enc.ErrFormat{}, err)
	buf = []byte(":/?#[]@")
	c = enc.Component{enc.TypeGenericNameComponent, buf}
	require.Equal(t, "%3A%2F%3F%23%5B%5D%40", c.String())
	c2 = utils.WithoutErr(enc.ComponentFromStr("%3A%2F%3F%23%5B%5D%40"))
	require.Equal(t, c, c2)

	err = utils.WithErr(enc.ComponentFromStr("/"))
	require.IsType(t, enc.ErrFormat{}, err)
	c = enc.Component{enc.TypeGenericNameComponent, []byte{}}
	require.Equal(t, "", c.String())
	require.Equal(t, c.Bytes(), []byte("\x08\x00"))
	c2 = utils.WithoutErr(enc.ComponentFromStr(""))
	require.Equal(t, c, c2)
}

func TestComponentTypes(t *testing.T) {
	utils.SetTestingT(t)

	hexText := "28bad4b5275bd392dbb670c75cf0b66f13f7942b21e80f55c0e86b374753a548"
	value := utils.WithoutErr(hex.DecodeString(hexText))

	buf := make([]byte, len(value)+2)
	buf[0] = byte(enc.TypeImplicitSha256DigestComponent)
	buf[1] = 0x20
	copy(buf[2:], value)
	c := utils.WithoutErr(enc.ComponentFromBytes(buf))
	require.Equal(t, enc.Component{enc.TypeImplicitSha256DigestComponent, value}, c)
	require.Equal(t, "sha256digest="+hexText, c.String())
	c2 := utils.WithoutErr(enc.ComponentFromStr("sha256digest=" + hexText))
	require.Equal(t, c, c2)
	c2 = utils.WithoutErr(enc.ComponentFromStr("sha256digest=" + strings.ToUpper(hexText)))
	require.Equal(t, c, c2)

	buf = make([]byte, len(value)+2)
	buf[0] = byte(enc.TypeParametersSha256DigestComponent)
	buf[1] = 0x20
	copy(buf[2:], value)
	c = utils.WithoutErr(enc.ComponentFromBytes(buf))
	require.Equal(t, enc.Component{enc.TypeParametersSha256DigestComponent, value}, c)
	require.Equal(t, "params-sha256="+hexText, c.String())
	c2 = utils.WithoutErr(enc.ComponentFromStr("params-sha256=" + hexText))
	require.Equal(t, c, c2)
	c2 = utils.WithoutErr(enc.ComponentFromStr("params-sha256=" + strings.ToUpper(hexText)))
	require.Equal(t, c, c2)

	c = utils.WithoutErr(enc.ComponentFromBytes([]byte{0x09, 0x03, '9', 0x3d, 'A'}))
	require.Equal(t, "9=9%3DA", c.String())
	require.Equal(t, 9, int(c.Typ))
	c2 = utils.WithoutErr(enc.ComponentFromStr("9=9%3DA"))
	require.Equal(t, c, c2)

	c = utils.WithoutErr(enc.ComponentFromBytes([]byte{0xfd, 0xff, 0xff, 0x00}))
	require.Equal(t, "65535=", c.String())
	require.Equal(t, 0xffff, int(c.Typ))
	c2 = utils.WithoutErr(enc.ComponentFromStr("65535="))
	require.Equal(t, c, c2)

	c = utils.WithoutErr(enc.ComponentFromBytes([]byte{0xfd, 0x57, 0x65, 0x01, 0x2e}))
	require.Equal(t, "22373=.", c.String())
	require.Equal(t, 0x5765, int(c.Typ))
	c2 = utils.WithoutErr(enc.ComponentFromStr("22373=%2e"))
	require.Equal(t, c, c2)

	utils.WithErr(enc.ComponentFromStr("0=A"))
	utils.WithErr(enc.ComponentFromStr("-1=A"))
	utils.WithErr(enc.ComponentFromStr("+=A"))
	utils.WithErr(enc.ComponentFromStr("1=2=A"))
	utils.WithErr(enc.ComponentFromStr("==A"))
	utils.WithErr(enc.ComponentFromStr("%%"))
	utils.WithErr(enc.ComponentFromStr("ABCD%EF%0"))
	utils.WithErr(enc.ComponentFromStr("ABCD%GH"))
	utils.WithErr(enc.ComponentFromStr("sha256digest=a04z"))
	utils.WithErr(enc.ComponentFromStr("65536=a04z"))

	require.Equal(t, []byte("\x32\x01\r"), enc.NewSegmentComponent(13).Bytes())
	require.Equal(t, []byte("\x34\x01\r"), enc.NewByteOffsetComponent(13).Bytes())
	require.Equal(t, []byte("\x3a\x01\r"), enc.NewSequenceNumComponent(13).Bytes())
	require.Equal(t, []byte("\x36\x01\r"), enc.NewVersionComponent(13).Bytes())
	tm := uint64(15686790223318112)
	require.Equal(t, []byte("\x38\x08\x00\x37\xbb\x0d\x76\xed\x4c\x60"), enc.NewTimestampComponent(tm).Bytes())
}

func TestComponentCompare(t *testing.T) {
	utils.SetTestingT(t)

	comps := []enc.Component{
		{1, utils.WithoutErr(hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000"))},
		{1, utils.WithoutErr(hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001"))},
		{1, utils.WithoutErr(hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"))},
		{2, utils.WithoutErr(hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000"))},
		{2, utils.WithoutErr(hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001"))},
		{2, utils.WithoutErr(hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"))},
		{3, []byte{}},
		{3, []byte{0x44}},
		{3, []byte{0x46}},
		{3, []byte{0x41, 0x41}},
		utils.WithoutErr(enc.ComponentFromStr("")),
		utils.WithoutErr(enc.ComponentFromStr("D")),
		utils.WithoutErr(enc.ComponentFromStr("F")),
		utils.WithoutErr(enc.ComponentFromStr("AA")),
		utils.WithoutErr(enc.ComponentFromStr("21426=")),
		utils.WithoutErr(enc.ComponentFromStr("21426=%44")),
		utils.WithoutErr(enc.ComponentFromStr("21426=%46")),
		utils.WithoutErr(enc.ComponentFromStr("21426=%41%41")),
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

func TestNameBasic(t *testing.T) {
	utils.SetTestingT(t)

	uri := "/Emid/25042=P3//./%1C%9F/sha256digest=0415e3624a151850ac686c84f155f29808c0dd73819aa4a4c20be73a4d8a874c"
	name := utils.WithoutErr(enc.NameFromStr(uri))
	require.Equal(t, 6, len(name))
	require.Equal(t, utils.WithoutErr(enc.ComponentFromStr("Emid")), name[0])
	require.Equal(t, utils.WithoutErr(enc.ComponentFromBytes([]byte("\xfd\x61\xd2\x02\x50\x33"))), name[1])
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

func TestNameString(t *testing.T) {
	utils.SetTestingT(t)

	tester := func(sIn, sOut string) {
		require.Equal(t, sOut, utils.WithoutErr(enc.NameFromStr(sIn)).String())
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

func TestNameCompare(t *testing.T) {
	utils.SetTestingT(t)

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
		names[i] = utils.WithoutErr(enc.NameFromStr(s))
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

func TestNameIsPrefix(t *testing.T) {
	utils.SetTestingT(t)

	testTrue := func(s1, s2 string) {
		n1 := utils.WithoutErr(enc.NameFromStr(s1))
		n2 := utils.WithoutErr(enc.NameFromStr(s2))
		require.True(t, n1.IsPrefix(n2))
	}
	testFalse := func(s1, s2 string) {
		n1 := utils.WithoutErr(enc.NameFromStr(s1))
		n2 := utils.WithoutErr(enc.NameFromStr(s2))
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

func TestNameBytes(t *testing.T) {
	utils.SetTestingT(t)

	n := utils.WithoutErr(enc.NameFromStr("/a/b/c/d"))
	require.Equal(t, []byte("\x07\x0c\x08\x01a\x08\x01b\x08\x01c\x08\x01d"), n.Bytes())
	require.Equal(t, []byte("\x07\x00"), enc.Name{}.Bytes())

	n2 := utils.WithoutErr(enc.NameFromBytes([]byte("\x07\x0c\x08\x01a\x08\x01b\x08\x01c\x08\x01d")))
	require.True(t, n.Equal(n2))
}

func TestNameAppend(t *testing.T) {
	utils.SetTestingT(t)

	// This section illustrates the issue with using append()
	// If we have a prefix which has an underlying array larger than the slice itself,
	// then subsequent appends will modify the same array. This will overwrite any
	// names created from the same prefix.
	prefix := utils.WithoutErr(enc.NameFromStr("/a/b/c/z/z/z"))[:3]
	name1 := append(prefix, utils.WithoutErr(enc.NameFromStr("d1/e1/f1"))...)
	name2 := append(prefix, utils.WithoutErr(enc.NameFromStr("d2/e2/f2"))...)
	require.Equal(t, name1.String(), name2.String()) // should not be equal

	// This section illustrates the correct way to append names
	// The Append function allocates a new array for the new name
	name3 := prefix.Append(utils.WithoutErr(enc.NameFromStr("d3/e3/f3"))...)
	name4 := prefix.Append(utils.WithoutErr(enc.NameFromStr("d4/e4/f4"))...)
	require.Equal(t, "/a/b/c/d3/e3/f3", name3.String())
	require.Equal(t, "/a/b/c/d4/e4/f4", name4.String())
}

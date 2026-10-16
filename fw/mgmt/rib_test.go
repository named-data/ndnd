/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package mgmt

import (
	"testing"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	"github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nniTlv encodes a TLV element holding a non-negative integer with the given
// value width, as used inside a PrefixAnnouncement content.
func nniTlv(typ byte, val uint64, width int) []byte {
	out := []byte{typ, byte(width)}
	for i := width - 1; i >= 0; i-- {
		out = append(out, byte(val>>(8*i)))
	}
	return out
}

func makePrefixAnnouncement(t *testing.T, name enc.Name, content []byte) ndn.Data {
	t.Helper()
	encoded, err := spec.Spec{}.MakeData(name, &ndn.DataConfig{
		ContentType: optional.Some(ndn.ContentTypePrefixAnnouncement),
	}, enc.Wire{content}, signer.NewSha256Signer())
	require.NoError(t, err)
	data, _, err := spec.Spec{}.ReadData(enc.NewWireView(encoded.Wire))
	require.NoError(t, err)
	return data
}

func paName(t *testing.T, prefix string, suffix ...enc.Component) enc.Name {
	t.Helper()
	name, err := enc.NameFromStr(prefix)
	require.NoError(t, err)
	return append(name, suffix...)
}

// Unit test covering parsePrefixAnnouncement: NDNts-style versioned and keyword-only PA names, cost and ExpirationPeriod extraction in several NNI widths, skipping of ValidityPeriod and unknown elements, and rejection of malformed announcements.
func TestParsePrefixAnnouncement(t *testing.T) {
	expiration := nniTlv(0x6d, 600000, 4)

	// NDNts-style name: announced prefix + 32=PA + version + segment 0.
	// A ValidityPeriod element in the content is skipped.
	validity := []byte{0xfd, 0x00, 0xfd, 0x02, 0x00, 0x00}
	data := makePrefixAnnouncement(t,
		paName(t, "/localhost/demo-prefixann",
			enc.NewKeywordComponent("PA"), enc.NewVersionComponent(123), enc.NewSegmentComponent(0)),
		append(validity, expiration...))
	prefix, expiry, cost, err := parsePrefixAnnouncement(data)
	require.NoError(t, err)
	assert.Equal(t, "/localhost/demo-prefixann", prefix.String())
	assert.Equal(t, 600*time.Second, expiry)
	assert.Equal(t, uint64(0), cost)

	// Keyword-only name without version and segment components.
	data = makePrefixAnnouncement(t,
		paName(t, "/a/b", enc.NewKeywordComponent("PA")),
		expiration)
	prefix, _, _, err = parsePrefixAnnouncement(data)
	require.NoError(t, err)
	assert.Equal(t, "/a/b", prefix.String())

	// Route cost is taken from the content when present.
	data = makePrefixAnnouncement(t,
		paName(t, "/a/b", enc.NewKeywordComponent("PA")),
		append(nniTlv(0x6a, 5, 1), expiration...))
	_, _, cost, err = parsePrefixAnnouncement(data)
	require.NoError(t, err)
	assert.Equal(t, uint64(5), cost)

	// One-byte ExpirationPeriod is accepted.
	data = makePrefixAnnouncement(t,
		paName(t, "/a/b", enc.NewKeywordComponent("PA")),
		nniTlv(0x6d, 100, 1))
	_, expiry, _, err = parsePrefixAnnouncement(data)
	require.NoError(t, err)
	assert.Equal(t, 100*time.Millisecond, expiry)

	// ExpirationPeriod is required.
	data = makePrefixAnnouncement(t,
		paName(t, "/a/b", enc.NewKeywordComponent("PA")),
		nniTlv(0x6a, 5, 1))
	_, _, _, err = parsePrefixAnnouncement(data)
	require.Error(t, err)

	// An NNI with a non-standard width is rejected.
	data = makePrefixAnnouncement(t,
		paName(t, "/a/b", enc.NewKeywordComponent("PA")),
		nniTlv(0x6d, 600000, 3))
	_, _, _, err = parsePrefixAnnouncement(data)
	require.Error(t, err)

	// Name without a PA keyword component is rejected.
	data = makePrefixAnnouncement(t, paName(t, "/a/b"), expiration)
	_, _, _, err = parsePrefixAnnouncement(data)
	require.Error(t, err)

	// Announced prefix must not be empty.
	data = makePrefixAnnouncement(t,
		enc.Name{enc.NewKeywordComponent("PA"), enc.NewVersionComponent(123), enc.NewSegmentComponent(0)},
		expiration)
	_, _, _, err = parsePrefixAnnouncement(data)
	require.Error(t, err)
}

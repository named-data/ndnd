package ndncert

import (
	"testing"

	"github.com/named-data/ndnd/std/security/ndncert/tlv"
	"github.com/stretchr/testify/require"
)

func TestAeadMessageRejectsMalformedFields(t *testing.T) {
	for _, sizes := range [][2]int{{0, 0}, {11, 16}, {12, 15}, {13, 16}, {12, 17}} {
		var message AeadMessage
		require.Error(t, message.FromTLV(&tlv.CipherMsg{
			InitVec: make([]byte, sizes[0]), AuthNTag: make([]byte, sizes[1]),
		}))
	}
	var message AeadMessage
	require.Error(t, message.FromTLV(nil))
	require.NoError(t, message.FromTLV(&tlv.CipherMsg{
		InitVec: make([]byte, AeadSizeNonce), AuthNTag: make([]byte, AeadSizeTag),
	}))
}

package utils_test

import (
	"testing"
	"time"

	"github.com/named-data/ndnd/std/utils"
	"github.com/stretchr/testify/require"
)

func TestIdPtr(t *testing.T) {
	utils.SetTestingT(t)

	p := utils.IdPtr(uint64(42))
	require.Equal(t, uint64(42), *p)
}

func TestMakeTimestamp(t *testing.T) {
	utils.SetTestingT(t)

	date := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	require.Equal(t, uint64(1609459200000), utils.MakeTimestamp(date))
}

func TestConvertNonce(t *testing.T) {
	utils.SetTestingT(t)

	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	require.Equal(t, uint64(0x010203040506), *utils.ConvertNonce(nonce))

	nonce = []byte{0x42, 0x1C, 0xE1, 0x4B, 0x99, 0xFA, 0xA3}
	require.Equal(t, uint64(0x421ce14b99faa3), *utils.ConvertNonce(nonce))
}

package utils

import (
	"time"

	"golang.org/x/exp/constraints"
)

// IdPtr is the pointer version of id: 'a->'a
func IdPtr[T any](value T) *T {
	return &value
}

// ConvIntPtr converts an integer pointer to another type
func ConvIntPtr[A, B constraints.Integer](a *A) *B {
	if a == nil {
		return nil
	} else {
		b := B(*a)
		return &b
	}
}

func MakeTimestamp(t time.Time) uint64 {
	return uint64(t.UnixNano() / int64(time.Millisecond))
}

func ConvertNonce(nonce []byte) *uint64 {
	x := uint64(0)
	for _, b := range nonce {
		x = (x << 8) | uint64(b)
	}
	return &x
}

package utils

import (
	"time"

	"github.com/named-data/ndnd/std/types/optional"
	"golang.org/x/exp/constraints"
)

// NDNd version from source control
// Note: this is only defined in NDNd itself, not for other projects.
var NDNdVersion string = "unknown"

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

// (AI GENERATED DESCRIPTION): Converts a `time.Time` into a Unix‑epoch timestamp expressed in milliseconds, returned as a `uint64`.
func MakeTimestamp(t time.Time) uint64 {
	return uint64(t.UnixNano() / int64(time.Millisecond))
}

// (AI GENERATED DESCRIPTION): Converts a byte slice nonce into an unsigned 32‑bit integer and returns it wrapped in an optional.Optional.
func ConvertNonce(nonce []byte) (ret optional.Optional[uint32]) {
	x := uint32(0)
	for _, b := range nonce {
		x = (x << 8) | uint32(b)
	}
	ret.Set(x)
	return ret
}

// If is the ternary operator (eager evaluation)
func If[T any](cond bool, t, f T) T {
	if cond {
		return t
	} else {
		return f
	}
}

// HeaderEqual compares two slices for header equality
func HeaderEqual[T any](a, b []T) bool {
	return len(a) == len(b) && (len(a) == 0 || &a[0] == &b[0])
}

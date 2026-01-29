package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var testT *testing.T

// (AI GENERATED DESCRIPTION): Assigns the supplied *testing.T to the package‑level test variable for use by the test suite.
func SetT(t *testing.T) {
	testT = t
}

// (AI GENERATED DESCRIPTION): Asserts that the supplied error is nil (via the test framework) and returns the value `v`.
func NoErr[T any](v T, err error) T {
	require.NoError(testT, err)
	return v
}

// (AI GENERATED DESCRIPTION): Asserts that the supplied error is non‑nil (for testing) and then returns that error.
func Err[T any](_ T, err error) error {
	require.Error(testT, err)
	return err
}

// (AI GENERATED DESCRIPTION): Panics if `err` is non‑nil; otherwise returns the provided value `v`.
func NoErrB[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// (AI GENERATED DESCRIPTION): Panics if the supplied error is nil; otherwise returns the error unchanged (the first, generic argument is ignored).
func ErrB[T any](_ T, err error) error {
	if err == nil {
		panic("expected error")
	}
	return err
}

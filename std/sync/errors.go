package sync

import (
	"errors"
	"fmt"

	enc "github.com/named-data/ndnd/std/encoding"
)

var ErrSnapshot = errors.New("snapshot error")

type ErrSync struct {
	Publisher enc.Name
	BootTime  uint64
	Err       error
}

// (AI GENERATED DESCRIPTION): Formats an ErrSync into a human‑readable error string that includes the publisher, boot time, and underlying error.
func (e *ErrSync) Error() string {
	return fmt.Sprintf("sync error [%s][%d]: %v", e.Publisher, e.BootTime, e.Err)
}

// (AI GENERATED DESCRIPTION): Unwrap returns the underlying error stored in the `ErrSync` instance, enabling standard error unwrapping with `errors.Is` or `errors.As`.
func (e *ErrSync) Unwrap() error {
	return e.Err
}

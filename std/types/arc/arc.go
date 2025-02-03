// Arc is an atomically reference counted generic type.
package arc

import (
	"sync/atomic"
)

// Arc is an atomically reference counted generic type.
// It is specifically designed to be used in a pool.
type Arc[T any] struct {
	v T
	c atomic.Int32
	p *ArcPool[T]
}

// New creates a new Arc[T] with the given value.
func NewArc[T any](v T) *Arc[T] {
	return &Arc[T]{v: v}
}

// Load returns the value of the Arc[T].
func (a *Arc[T]) Load() T {
	return a.v
}

// Inc increments the reference count of the Arc[T].
func (a *Arc[T]) Inc() {
	a.c.Add(1)
}

// Dec decrements the reference count of the Arc[T].
func (a *Arc[T]) Dec() int32 {
	c := a.c.Add(-1)
	if c == 0 && a.p != nil {
		// fmt.Println("Arc: returning to pool")
		a.p.Put(a)
	}
	return c
}

// Lock-free data structures
package lockfree

import (
	"iter"
	"sync/atomic"
)

// YiQueue is a lock-free Yielding Queue.
//
// It is desgined to be used by a single consumer and multiple producers.
// Very little spin-locking is used; instead the ring will notify the
// consumer with a channel when the write rate is not keeping up with the
// read rate.
type YiQueue[T any] struct {
	Notify chan struct{}
	queue  *Queue[T]
	size   atomic.Int32
}

// (AI GENERATED DESCRIPTION): Creates and returns a new YiQueue[T] initialized with a one‑slot buffered notification channel and an empty underlying queue.
func NewYiQueue[T any]() *YiQueue[T] {
	return &YiQueue[T]{
		Notify: make(chan struct{}, 1),
		queue:  NewQueue[T](),
	}
}

// (AI GENERATED DESCRIPTION): Adds an element to the YiQueue and, if it was the first item, notifies the consumer through the Notify channel in a non‑blocking fashion.
func (yq *YiQueue[T]) Push(v T) {
	sizenow := yq.size.Add(1)
	yq.queue.Push(v)
	if sizenow == 1 && yq.size.Load() > 0 {
		// this is the first element in the queue
		// notify the consumer in a non-blocking way
		select {
		case yq.Notify <- struct{}{}:
		default:
		}
	}
}

// (AI GENERATED DESCRIPTION): Pops the next value from the queue (decrementing the size counter) and returns it with a success flag, spinning until any in‑flight push completes.
func (yq *YiQueue[T]) Pop() (val T, ok bool) {
	for yq.size.Load() > 0 {
		val, ok = yq.queue.Pop()
		if !ok {
			// spin-lock: we have been promised a value, but it
			// is still being inserted in the Push() call.
			continue
		}
		yq.size.Add(-1)
		return val, true
	}

	// queue is empty
	return val, false
}

// (AI GENERATED DESCRIPTION): Returns an iterator that repeatedly pops and yields items from the queue until the queue is empty or the supplied yield function returns false.
func (yq *YiQueue[T]) Iter() iter.Seq[T] {
	return func(yield func(T) bool) {
		for {
			val, ok := yq.Pop()
			if !ok || !yield(val) {
				return
			}
		}
	}
}

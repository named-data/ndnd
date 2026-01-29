package lockfree

import (
	"sync/atomic"
)

// Queue is a lock-free queue with a single consumer and multiple producers.
type Queue[T any] struct {
	head *node[T]
	tail atomic.Pointer[node[T]]
}

type node[T any] struct {
	val  T
	next atomic.Pointer[node[T]]
}

// (AI GENERATED DESCRIPTION): Creates a new empty concurrent queue by initializing a sentinel head node and setting both the head and tail pointers to that node.
func NewQueue[T any]() *Queue[T] {
	q := &Queue[T]{
		head: &node[T]{},
		tail: atomic.Pointer[node[T]]{},
	}
	q.tail.Store(q.head)
	return q
}

// (AI GENERATED DESCRIPTION): Adds a new element to the end of the lock‑free queue, atomically updating the tail pointer and linking the new node.
func (q *Queue[T]) Push(v T) {
	n := &node[T]{val: v}
	for {
		tail := q.tail.Load()
		if q.tail.CompareAndSwap(tail, n) {
			tail.next.Store(n)
			return
		}
	}
}

// (AI GENERATED DESCRIPTION): Pops and returns the front value of the queue, yielding `ok=false` if the queue is empty.
func (q *Queue[T]) Pop() (val T, ok bool) {
	next := q.head.next.Load()
	if next == nil {
		return val, false
	}
	q.head = next
	return next.val, true
}

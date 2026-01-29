package sync

import (
	"iter"

	enc "github.com/named-data/ndnd/std/encoding"
)

// SimplePs is a simple Pub/Sub system.
type SimplePs[V any] struct {
	// subs is the list of subscribers.
	subs map[string]SimplePsSub[V]
}

type SimplePsSub[V any] struct {
	// Prefix is the name prefix to subscribe.
	Prefix enc.Name
	// Callback is the callback function.
	Callback func(V)
}

// (AI GENERATED DESCRIPTION): Initializes a new SimplePs instance with an empty map of subscriptions.
func NewSimplePs[V any]() SimplePs[V] {
	return SimplePs[V]{
		subs: make(map[string]SimplePsSub[V]),
	}
}

// (AI GENERATED DESCRIPTION): Adds a subscription for the specified prefix, storing the provided callback to be executed when packets matching that prefix are received.
func (ps *SimplePs[V]) Subscribe(prefix enc.Name, callback func(V)) error {
	if callback == nil {
		panic("Callback is required for subscription")
	}

	ps.subs[prefix.TlvStr()] = SimplePsSub[V]{
		Prefix:   prefix,
		Callback: callback,
	}

	return nil
}

// (AI GENERATED DESCRIPTION): Unsubscribes the specified prefix by deleting its entry from the subscription map.
func (ps *SimplePs[V]) Unsubscribe(prefix enc.Name) {
	delete(ps.subs, prefix.TlvStr())
}

// (AI GENERATED DESCRIPTION): Returns a sequence of callback functions for all stored subscriptions whose registered prefixes are prefixes of the given prefix.
func (ps *SimplePs[V]) Subs(prefix enc.Name) iter.Seq[func(V)] {
	return func(yield func(func(V)) bool) {
		for _, sub := range ps.subs {
			if sub.Prefix.IsPrefix(prefix) {
				if !yield(sub.Callback) {
					return
				}
			}
		}
	}
}

// (AI GENERATED DESCRIPTION): Returns true if the prefix set contains at least one subscription that matches the supplied name prefix, otherwise false.
func (ps *SimplePs[V]) HasSub(prefix enc.Name) bool {
	for range ps.Subs(prefix) {
		return true
	}
	return false
}

// (AI GENERATED DESCRIPTION): Publishes the provided data to every active subscriber registered for the given name by invoking each subscriber callback with the data.
func (ps *SimplePs[V]) Publish(name enc.Name, data V) {
	for sub := range ps.Subs(name) {
		sub(data)
	}
}

package ndn

import enc "github.com/named-data/ndnd/std/encoding"

type Store interface {
	// Get returns a Data wire matching the given name
	// prefix = return the lexicographically last Data wire with the given prefix
	Get(name enc.Name, prefix bool) ([]byte, error)

	// Put inserts a Data wire into the store
	Put(name enc.Name, wire []byte) error

	// Remove removes a Data wire from the store
	Remove(name enc.Name) error
	// RemovePrefix remove all Data wires under a prefix
	RemovePrefix(prefix enc.Name) error
	// RemoveFlatRange removes (recursively) all subtrees under a range of
	// flat prefixes. This is useful for removing a range of segments or
	// sequence numbers that have the same prefix.
	// The removal is inclusive of the first and last element.
	//  i.e. RemoveFlatRange({/A/B}, 0, 3) removes {/A/B/0}, {/A/B/1}, {/A/B/2}, {/A/B/3}
	// The first and last components must be a number of the same type,
	// otherwise the behavior is undefined (since ordering is undefined)
	RemoveFlatRange(prefix enc.Name, first enc.Component, last enc.Component) error

	// Begin starts a write transaction (for put only)
	// we support these primarily for performance rather than correctness
	// do not rely on atomicity of transactions as far as possible
	Begin() (Store, error)
	// Commit commits a write transaction
	Commit() error
	// Rollback discards a write transaction
	Rollback() error
}

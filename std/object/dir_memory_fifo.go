package object

import (
	enc "github.com/named-data/ndnd/std/encoding"
)

// MemoryFifoDir is a simple object directory that evicts the oldest name
// when it reaches its size size.
type MemoryFifoDir struct {
	list []enc.Name
	size int
}

// NewMemoryFifoDir creates a new directory.
func NewMemoryFifoDir(size int) *MemoryFifoDir {
	return &MemoryFifoDir{
		list: make([]enc.Name, 0),
		size: size,
	}
}

// Push adds a name to the directory.
func (d *MemoryFifoDir) Push(name enc.Name) {
	d.list = append(d.list, name.Clone())
}

// Pop removes the oldest name from the directory and returns it.
// If the directory has not reached its size, it returns nil.
// It is recommended to use Evict() instead to remove objects from a client.
func (d *MemoryFifoDir) Pop() enc.Name {
	if len(d.list) < d.size {
		return nil
	}

	name := d.list[0]
	d.list = d.list[1:]
	return name
}

// Evict removes old names from a client until it reaches the desired size.
func (d *MemoryFifoDir) Evict(client *Client) error {
	for {
		name := d.Pop()
		if name == nil {
			return nil
		}

		if err := client.Remove(name); err != nil {
			return err
		}
	}
}

// Count returns the number of names in the directory.
func (d *MemoryFifoDir) Count() int {
	return len(d.list)
}

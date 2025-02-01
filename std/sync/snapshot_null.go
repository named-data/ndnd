package sync

import enc "github.com/named-data/ndnd/std/encoding"

// SnapshotNull is a non-snapshot strategy.
type SnapshotNull struct {
}

func (s *SnapshotNull) Snapshot() Snapshot {
	return s
}

func (s *SnapshotNull) onUpdate(args snapshotOnUpdateArgs) {
}

func (s *SnapshotNull) setCallback(enc.Name) {
}

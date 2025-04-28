package sync

import enc "github.com/named-data/ndnd/std/encoding"

// SnapshotNull is a non-snapshot strategy.
type SnapshotNull struct {
}

func (s *SnapshotNull) Snapshot() Snapshot {
	return s
}

func (s *SnapshotNull) initialize(snapPsState, SvMap[svsDataState]) {
}

func (s *SnapshotNull) onUpdate(SvMap[svsDataState], enc.Name) {
}

func (s *SnapshotNull) onPublication(SvMap[svsDataState], enc.Name) {
}

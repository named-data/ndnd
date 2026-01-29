package sync

import enc "github.com/named-data/ndnd/std/encoding"

// SnapshotNull is a non-snapshot strategy.
type SnapshotNull struct {
}

// (AI GENERATED DESCRIPTION): Returns the SnapshotNull instance itself as a Snapshot.
func (s *SnapshotNull) Snapshot() Snapshot {
	return s
}

// (AI GENERATED DESCRIPTION): Initializes a SnapshotNull instance with the supplied snapshot packet state and SVs data state map.
func (s *SnapshotNull) initialize(snapPsState, SvMap[svsDataState]) {
}

// (AI GENERATED DESCRIPTION): No-op update handler that ignores any update events for SnapshotNull.
func (s *SnapshotNull) onUpdate(SvMap[svsDataState], enc.Name) {
}

// (AI GENERATED DESCRIPTION): Handles snapshot publication events; currently a no‑op placeholder for the SnapshotNull type.
func (s *SnapshotNull) onPublication(SvMap[svsDataState], enc.Name) {
}

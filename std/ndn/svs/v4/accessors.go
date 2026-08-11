package svs

// VectorKind identifies which direct form an SvsData carries on the wire.
// Publish-only Sync Data carries neither FullStateVector nor
// PartialStateVector; instead it has SvsDataRef. The choice of wire TLV
// replaces the previous VectorType discriminator field.
type VectorKind int

const (
	// VectorKindNone is the publish-only form: no embedded vector, only a
	// retrievable SvsDataRef.
	VectorKindNone VectorKind = iota
	// VectorKindFull is a complete State Vector (FULL).
	VectorKindFull
	// VectorKindPartial is a sender-selected subset (PARTIAL).
	VectorKindPartial
)

// GetStateVector returns the embedded StateVector for direct forms (FULL
// or PARTIAL), or nil for the publish-only form.
func (d *SvsData) GetStateVector() *StateVector {
	switch {
	case d.FullStateVector != nil:
		return d.FullStateVector.StateVector
	case d.PartialStateVector != nil:
		return d.PartialStateVector.StateVector
	}
	return nil
}

// Kind reports which direct form (or none) the SvsData carries on the wire.
// An SvsData carrying both FullStateVector and PartialStateVector is
// reported as KindFull (the more specific case wins).
func (d *SvsData) Kind() VectorKind {
	switch {
	case d.FullStateVector != nil:
		return VectorKindFull
	case d.PartialStateVector != nil:
		return VectorKindPartial
	}
	return VectorKindNone
}

// IsPartial reports whether the embedded StateVector is a PARTIAL subset.
// Returns false for the publish-only form (callers that branch on this
// should also check SvsDataRef for the publish-only recovery path).
func (d *SvsData) IsPartial() bool {
	return d.PartialStateVector != nil
}

// IsFull reports whether the embedded StateVector is a FULL State Vector.
func (d *SvsData) IsFull() bool {
	return d.FullStateVector != nil
}

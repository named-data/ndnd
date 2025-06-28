package sync

import (
	"fmt"

	enc "github.com/named-data/ndnd/std/encoding"
	spec_svsps "github.com/named-data/ndnd/std/ndn/svs_ps"
)

// instanceState returns the current state of the instance.
func (s *SvsALO) instanceState() enc.Wire {
	state := spec_svsps.InstanceState{
		Name:          s.opts.Name,
		BootstrapTime: s.BootTime(),
		StateVector: s.state.Encode(func(state svsDataState) uint64 {
			return state.Known
		}),
	}
	return state.Encode()
}

// parseInstanceState parses an instance state into the current state.
// Only the constructor should call this function.
func (s *SvsALO) parseInstanceState(wire enc.Wire) error {
	initState, err := spec_svsps.ParseInstanceState(enc.NewWireView(wire), true)
	if err != nil {
		return err
	}

	if !initState.Name.Equal(s.opts.Name) {
		return fmt.Errorf("initial state name mismatch: %v != %v", initState.Name, s.opts.Name)
	}

	s.opts.Svs.BootTime = initState.BootstrapTime
	s.opts.Svs.InitialState = initState.StateVector

	for _, entry := range initState.StateVector.Entries {
		hash := entry.Name.TlvStr()
		for _, seqEntry := range entry.SeqNoEntries {
			s.state.Set(hash, seqEntry.BootstrapTime, svsDataState{
				Known:   seqEntry.SeqNo,
				Latest:  seqEntry.SeqNo,
				Pending: seqEntry.SeqNo,
			})
		}
	}

	return nil
}

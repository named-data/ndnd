package mgmt_2022

import "fmt"

type Persistency uint64

const (
	PersistencyPersistent Persistency = 0
	PersistencyOnDemand   Persistency = 1
	PersistencyPermanent  Persistency = 2
)

var PersistencyList = map[Persistency]string{
	PersistencyPersistent: "persistent",
	PersistencyOnDemand:   "on-demand",
	PersistencyPermanent:  "permanent",
}

// (AI GENERATED DESCRIPTION): Returns the string representation of a Persistency value from PersistencyList, or “unknown” if the value is not defined.
func (p Persistency) String() string {
	if s, ok := PersistencyList[p]; ok {
		return s
	}
	return "unknown"
}

// (AI GENERATED DESCRIPTION): Parses a string into the corresponding Persistency enum value, returning an error if the string does not match any known persistency.
func ParsePersistency(s string) (Persistency, error) {
	for k, v := range PersistencyList {
		if v == s {
			return k, nil
		}
	}
	return 0, fmt.Errorf("unknown persistency")
}

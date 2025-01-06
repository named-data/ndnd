package mgmt_2022

import "errors"

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

func (p Persistency) String() string {
	if s, ok := PersistencyList[p]; ok {
		return s
	}
	return "unknown"
}

func ParsePersistency(s string) (Persistency, error) {
	for k, v := range PersistencyList {
		if v == s {
			return k, nil
		}
	}
	return 0, errors.New("unknown persistency")
}

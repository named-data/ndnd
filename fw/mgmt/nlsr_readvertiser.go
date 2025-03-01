package mgmt

import (
	"sync"

	"github.com/named-data/ndnd/fw/core"
	"github.com/named-data/ndnd/fw/table"
	enc "github.com/named-data/ndnd/std/encoding"
	spec_mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/named-data/ndnd/std/types/optional"
)

// Simple readvertiser that echoes the register command to NLSR.
// Currently the command is one-shot, and does not handle failures.
type NlsrReadvertiser struct {
	m *Thread
	// List of routes already advertised to NLSR
	advertised map[uint64]int // hash -> count
	// This is called from RIB (i.e. could be fw threads)
	mutex sync.Mutex
}

func NewNlsrReadvertiser(m *Thread) *NlsrReadvertiser {
	return &NlsrReadvertiser{
		m:          m,
		advertised: make(map[uint64]int),
	}
}

func (r *NlsrReadvertiser) String() string {
	return "mgmt-nlsr-readvertiser"
}

func (r *NlsrReadvertiser) Announce(name enc.Name, route *table.Route) {
	if route.Origin != uint64(spec_mgmt.RouteOriginClient) {
		core.Log.Debug(r, "Skip advertise", "name", name, "origin", route.Origin)
		return
	}
	core.Log.Info(r, "Advertise", "name", name)

	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.advertised[name.Hash()] += 1

	params := &spec_mgmt.ControlArgs{
		Name:   name,
		Origin: optional.Some(route.Origin),
		Cost:   optional.Some(route.Cost),
	}

	nameParams := &spec_mgmt.ControlParameters{
		Val: &spec_mgmt.ControlArgs{Name: name},
	}

	cmd := enc.Name{enc.LOCALHOST,
		enc.NewGenericComponent("nlsr"),
		enc.NewGenericComponent("rib"),
		enc.NewGenericComponent("register"),
		enc.NewGenericBytesComponent(nameParams.Encode().Join()),
	}

	r.m.sendInterest(cmd, params.Encode())
}

func (r *NlsrReadvertiser) Withdraw(name enc.Name, route *table.Route) {
	if route.Origin != uint64(spec_mgmt.RouteOriginClient) {
		core.Log.Debug(r, "Skip withdraw (origin)", "name", name, "origin", route.Origin)
		return
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	nhash := name.Hash()
	r.advertised[nhash] -= 1
	if r.advertised[nhash] > 0 {
		core.Log.Debug(r, "Skip withdraw (still advertised)", "name", name)
		return
	}
	core.Log.Info(r, "Withdraw", "name", name)

	params := &spec_mgmt.ControlArgs{
		Name:   name,
		Origin: optional.Some(route.Origin),
	}

	nameParams := &spec_mgmt.ControlParameters{
		Val: &spec_mgmt.ControlArgs{Name: name},
	}

	cmd := enc.Name{enc.LOCALHOST,
		enc.NewGenericComponent("nlsr"),
		enc.NewGenericComponent("rib"),
		enc.NewGenericComponent("unregister"),
		enc.NewGenericBytesComponent(nameParams.Encode().Join()),
	}

	r.m.sendInterest(cmd, params.Encode())
}

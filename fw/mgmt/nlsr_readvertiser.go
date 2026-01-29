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
	// This is called from RIB (i.e. could be fw threads)
	mutex sync.Mutex
}

// (AI GENERATED DESCRIPTION): Creates a new NlsrReadvertiser instance and associates it with the supplied Thread.
func NewNlsrReadvertiser(m *Thread) *NlsrReadvertiser {
	return &NlsrReadvertiser{m: m}
}

// (AI GENERATED DESCRIPTION): Returns the constant string “mgmt-nlsr-readvertiser”, serving as the human‑readable identifier for the NlsrReadvertiser (used in logs, debugging, or fmt.Stringer output).
func (r *NlsrReadvertiser) String() string {
	return "mgmt-nlsr-readvertiser"
}

// (AI GENERATED DESCRIPTION): Announces a client‑originated route by sending an RIB register interest containing the route’s name, face ID, and cost to the NLSR.
func (r *NlsrReadvertiser) Announce(name enc.Name, route *table.Route) {
	if route.Origin != uint64(spec_mgmt.RouteOriginClient) {
		return
	}
	core.Log.Info(r, "NlsrAdvertise", "name", name)

	r.mutex.Lock()
	defer r.mutex.Unlock()

	params := &spec_mgmt.ControlParameters{
		Val: &spec_mgmt.ControlArgs{
			Name:   name,
			FaceId: optional.Some(route.FaceID),
			Cost:   optional.Some(route.Cost),
		},
	}

	cmd := enc.Name{enc.LOCALHOST,
		enc.NewGenericComponent("nlsr"),
		enc.NewGenericComponent("rib"),
		enc.NewGenericComponent("register"),
		enc.NewGenericBytesComponent(params.Encode().Join()),
	}

	r.m.sendInterest(cmd, enc.Wire{})
}

// (AI GENERATED DESCRIPTION): Sends an unregister interest to the NLSR to withdraw a client‑originated route from the routing table.
func (r *NlsrReadvertiser) Withdraw(name enc.Name, route *table.Route) {
	if route.Origin != uint64(spec_mgmt.RouteOriginClient) {
		return
	}
	core.Log.Info(r, "NlsrWithdraw", "name", name)

	r.mutex.Lock()
	defer r.mutex.Unlock()

	params := &spec_mgmt.ControlParameters{
		Val: &spec_mgmt.ControlArgs{
			Name:   name,
			FaceId: optional.Some(route.FaceID),
		},
	}

	cmd := enc.Name{enc.LOCALHOST,
		enc.NewGenericComponent("nlsr"),
		enc.NewGenericComponent("rib"),
		enc.NewGenericComponent("unregister"),
		enc.NewGenericBytesComponent(params.Encode().Join()),
	}

	r.m.sendInterest(cmd, enc.Wire{})
}

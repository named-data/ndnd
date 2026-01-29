package table

import enc "github.com/named-data/ndnd/std/encoding"

// Readvertising instances
var readvertisers = make([]RibReadvertise, 0)

type RibReadvertise interface {
	// Advertise a route in the RIB
	Announce(name enc.Name, route *Route)
	// Remove a route from the RIB
	Withdraw(name enc.Name, route *Route)
}

// (AI GENERATED DESCRIPTION): Adds the supplied RibReadvertise instance to the global list of readvertisers.
func AddReadvertiser(r RibReadvertise) {
	readvertisers = append(readvertisers, r)
}

// (AI GENERATED DESCRIPTION): Notifies every registered readvertiser of a new route for the specified name by calling its Announce method.
func readvertiseAnnounce(name enc.Name, route *Route) {
	for _, r := range readvertisers {
		r.Announce(name, route)
	}
}

// (AI GENERATED DESCRIPTION): Instructs all registered readvertisers to withdraw the specified name on the given route.
func readvertiseWithdraw(name enc.Name, route *Route) {
	for _, r := range readvertisers {
		r.Withdraw(name, route)
	}
}

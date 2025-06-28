# ndn-dv specification

This page describes the protocol specification of NDN Distance Vector Routing (ndn-dv).

## 1. Basic Protocol Design

1. All routers must have a unique *name* in the network for identification,
   and routers should be able to mutually authenticate each other.

1. Every router maintains a Routing Information Base (RIB) and
   computes a single *Advertisement* every time the RIB changes.
   The Advertisement is synchronized with all *neighbors* using a
   router-specific State Vector Sync group (*Advertisement Sync* group).

1. All routers join a global *Prefix Sync* SVS group to synchronize the
   global prefix table, which contains the mapping of prefixes to
   routers that can reach them.

## 2. Format and Naming

```
Advertisement Broadcast Interest  = /localhop/<network>/32=DV/32=ADS/32=ACT
Advertisement Broadcast Interest  = /localhop/<network>/32=DV/32=ADS/32=PSV
Advertisement Broadcast Data      = /localhop/<router>/32=DV/32=ADV/32=SYNC
Advertisement Data                = /localhop/<router>/32=DV/32=ADV/t=<boot>/v=<seq>
Prefix Group SVS                  = /<network>/32=DV/32=PFS/32=svs
Prefix Data                       = /<network>/32=DV/32=PFS/<router>/t=<boot>/seq=<seq>/v=0
Prefix Snapshot                   = /<network>/32=DV/32=PFS/<router>/t=<boot>/32=SNAP/v=<seq>

<router>  = router's unique name in the network
<network> = globally unique network prefix
```

## 3. TLV Specification

```abnf
Advertisement = ADVERTISEMENT-TYPE TLV-LENGTH
                *AdvEntry

Interface = INTERFACE-TYPE TLV-LENGTH NonNegativeInteger
Neighbor = NEIGHBOR-TYPE TLV-LENGTH Name

AdvEntry = ADV-ENTRY-TYPE TLV-LENGTH
           Destination
           NextHop
           Cost
           OtherCost

Destination = DESTINATION-TYPE TLV-LENGTH Name
NextHop = NEXT-HOP-TYPE TLV-LENGTH Name
Cost = COST-TYPE TLV-LENGTH NonNegativeInteger
OtherCost = OTHER-COST-TYPE TLV-LENGTH NonNegativeInteger

ADVERTISEMENT-TYPE = 201
ADV-ENTRY-TYPE = 202
DESTINATION-TYPE = 204
NEXT-HOP-TYPE = 206
COST-TYPE = 208
OTHER-COST-TYPE = 210
```

```abnf
PrefixOpList = PREFIX-OP-LIST-TYPE TLV-LENGTH
               ExitRouter
               [*PrefixOpReset]
               [*PrefixOpAdd]
               [*PrefixOpRemove]

ExitRouter = DESTINATION-TYPE TLV-LENGTH Name
PrefixOpReset = PREFIX-OP-RESET-TYPE TLV-LENGTH
PrefixOpAdd = PREFIX-OP-ADD-TYPE TLV-LENGTH
              Name
              Cost
PrefixOpRemove = PREFIX-OP-REMOVE-TYPE TLV-LENGTH
                 Name

PREFIX-OP-LIST-TYPE = 301
PREFIX-OP-RESET-TYPE = 302
PREFIX-OP-ADD-TYPE = 304
PREFIX-OP-REMOVE-TYPE = 306
```

## 4. Protocol Operation

### RIB State

Each router maintains a list of RIB entries as the RIB state. Each RIB entry
contains the following fields:

1. `Destination`: name of the destination router.
1. `Cost`: cost to reach destination through this interface (one for each interface).

### Advertisement Computation

A new advertisement is computed by the router whenever the RIB changes.
One `AdvEntry` is generated for each RIB entry and contains the following fields:

1. `Destination`: name of the destination router.
1. `NextHop`: name of the router for reaching the destination with lowest cost.
1. `Cost`: Cost associated with the *best* next-hop interface.
1. `OtherCost`: Cost associated with the *second-best* next-hop interface.

Notes:

1. If multiple next hops have the same cost, the router MUST break ties consistently. Implementations MAY choose the next hop with the lexicographically lowest name.
1. If the advertisement changes, the router increments the sequence number for the *Advertisement Sync* group.
1. Neighbor is considered dead if no update is received for the `RouterDeadInterval` period.

### Advertisement Broadcast

ndn-dv uses a local variant of SVS v3 for advertisement broadcast. The name of the Interest and encapsulated Data (in ApplicationParameters) are provided in the format and naming section.

1. Each router maintains a local sequence number that is incremented when the advertisement changes.
1. Sync Interests are encoded identical to SVS, but the state vector ONLY contains the router's own sequence number.
1. Sync Interests are propagated only one hop, using `localhop` and a `HopLimit` of 2.
1. On receiving a Sync Interest, the router updates the sequence number for the sending neighbor.
1. However, the outgoing state vector does not change, and always only contains the router itself.
1. The incoming face of a Advertisement Broadcast Interest is used to set up data routes to neighbors.

To allow for asymmetric face configurations, two types of Sync Interests are used:

1. Active Advertisement Sync Interests are sent to neighbors explicity registered with the router. These are multicast to all neighbors by registering a FIB entry for the active Sync prefix.
2. Passive Advertisement Sync Interests are sent to all neighbors, on the incoming face of the neighbor's Sync Interest. These are multicast to all neighbors by registering a FIB entry for the passive Sync prefix.
3. When processing a Sync Interest, an active Sync Interest always takes precedence over any passive Sync Interest for purposes of determining the outgoing face to a neighbor.

### Update Processing

On receiving a new advertisement from a neighbor, the router processes the advertisement as follows:

```python
for n in neighbors:
  if n.advertisement is None:
    continue

  for entry in n.advertisement:
    cost = entry.cost + 1

    if entry.nexthop is self:
      if entry.other < INFINITY:
        cost = entry.other + 1
      else:
        cost = INFINITY

    if cost >= INFINITY:
      continue

    rib[entry.destination][n.interface] = cost
```

`INFINITY` is the maximum cost value, set to `16` by default.

### Prefix Sync

Each router maintains a global prefix table that maps prefixes to routers that can reach them.

1. When any router makes a change to their local prefix list, it increments the
   sequence number for the *Prefix Sync* group, and publishes a `PrefixOpList`
   message. The contents of the `PrefixOpList` must be processed strictly in order.

1. When a router starts, it sends a `PREFIX-OP-RESET` operation.
   This clears all prefix entries for the sender at all routers.

1. When a router adds a new prefix, it sends a `PREFIX-OP-ADD` operation.
   If the cost is updated, the router sends a `PREFIX-OP-ADD` with the new cost.

1. When a router removes a prefix, it sends a `PREFIX-OP-REMOVE` operation.

### FIB Computation

The FIB is configured based on the RIB state and the global prefix table.

1. For each prefix in the global prefix table, the router selects the lowest-cost
   next-hop interface from the RIB state and installs a FIB entry.

1. If the prefix is not reachable, any existing FIB entry is removed.

1. If the prefix is reachable through multiple interfaces, the router installs
   multiple FIB entries, one for each interface.

1. When a prefix destination has multiple exit routers, the router chooses the exit
   router that it can reach with the lowest cost.

### Security

The LightVerSec policy for ndn-dv is described in [config/schema.trust](./config/schema.trust).

All routers must have a unique name configured in the network, and a global common network name. ndn-dv data is signed using the router's key, which in turn is signed by the network key (trust anchor).

When fetching certificates, the name of the data being verified MUST be attached as a forwarding hint to all certificate Interests in the chain.

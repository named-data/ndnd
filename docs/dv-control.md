# DV Control Reference

This is the detailed reference for the ndn-dv routing daemon control tool.

## Routing status dataset

Each DV router serves a read-only dataset at
`/<router-name>/32=DV/32=STATUS`. For example:

```sh
ndnd cat /example/a/32=DV/32=STATUS > routing-status.tlv
```

The content is a `dv/tlv.RoutingStatus` snapshot of the responding router's
view: its general status and all reachable routers, with each router's
selected next hop, routing cost, and learned prefix announcements and costs.
Unreachable routers are omitted. Router and prefix entries are sorted by NDN
name. This reports distance-vector reachability, rather than an NLSR
link-state database or a complete graph of physical links.

Fetch the unversioned name using the object client's `Consume` API. RDR
metadata identifies a versioned, segmented object with a FinalBlockId.
Snapshots have one-second freshness and a bounded history of recent versions
is retained for in-progress segment fetches. Snapshot generation does not run
on the engine's packet-processing loop.

Secure routers sign metadata and data segments with their configured DV
router key. Consumers should validate using the DV trust schema and their
network's trust anchors. DV routers install routes for other reachable
routers' dataset prefixes, so queries can cross multiple upgraded DV hops.
For remote validation, set `trust.UseDataNameFwHint = true` on the consumer's
`security.TrustConfig` unless the certificate names are independently routable.
This sends certificate Interests with the original Data name as a forwarding
hint, allowing them to follow the dataset route back to its producer. The
dataset routes alone do not route certificate names. DV routers already enable
this option on their own trust configuration.
The existing `/localhost/nlsr/status` summary remains available.

The dataset content has these TLV fields. The complete wire grammar, including
the nested status fields, is specified in the
[routing status dataset specification](../dv/SPEC.md#routing-status-dataset).

| Field | Type | Value |
|---|---|---|
| Status | `0x1A0` | Existing DV Status fields |
| Router (repeated) | `0x1A2` | Name, NextHop, Cost, and Prefix fields |
| Name | `0x07` | Router or announced prefix name |
| NextHop | `0xCE` | Destination containing the selected router name |
| Cost | `0xD0` | Non-negative integer |
| Prefix (repeated within Router) | `0x130` | Announced Name and Cost |

## `ndnd dv link-create`

The link-create command creates a new neighbor link. A new permanent face will be created for the neighbor if a matching face does not exist.

```bash
# Create a UDP neighbor link
ndnd dv link-create udp://suns.cs.ucla.edu

# Create a TCP neighbor link
ndnd dv link-create tcp4://hobo.cs.arizona.edu:6363
```

## `ndnd dv link-destroy`

The link-destroy command destroys a neighbor link. The face associated with the neighbor will be destroyed.

```bash
# Destroy a neighbor link by URI
ndnd dv link-destroy udp://suns.cs.ucla.edu
```

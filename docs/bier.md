# BIER in NDNd

BIER (Bit Index Explicit Replication) provides stateless multicast forwarding for interests in NDNd.
Multicast forwarding for interests is primarily used for svs sync, either at the application level or by the routers to agree upon routing state.
Without BIER, multicast is still supported, but the interest will flood the network as a fallback (ideally, this is only used for routing state agreement).

Each router that participates in BIER also needs a unique BIER bit index configured in the forwarder YAML under `fw.bier_index` (defaulting to `-1` for routers lacking BIER support), for example:

```yaml
fw:
  bier_index: 3
```

Currently, on each router in a BIER-enabled network, operator must run `ndnd fw bift-register prefix=<router-name> index=<bfr-id>` for every `(router-name, bfr-id)` that exists in the network, then build the BIFT (BIER state representing forwarding trees) using `ndnd fw bift-rebuild`.

To inspect the resulting forwarding state, use `ndnd fw bift-list`.

## BIFT Status TLV Specification

`/localhost/nfd/bift/list` returns a snapshot of the BIFT. The reassembled
dataset payload contains the following fields:

```abnf
BiftStatus = BiftVersion [BierIndex] *BiftEntry *BiftNeighbor
BiftVersion = BIFT-VERSION-TYPE TLV-LENGTH NonNegativeInteger
BierIndex = BIER-INDEX-TYPE TLV-LENGTH NonNegativeInteger
BiftEntry = BIFT-ENTRY-TYPE TLV-LENGTH
            Name BfrId *NextHop *EntryForwardingBit
BfrId = BFR-ID-TYPE TLV-LENGTH NonNegativeInteger
NextHop = NEXT-HOP-TYPE TLV-LENGTH NonNegativeInteger
EntryForwardingBit = ENTRY-FORWARDING-BIT-TYPE TLV-LENGTH NonNegativeInteger
BiftNeighbor = BIFT-NEIGHBOR-TYPE TLV-LENGTH FaceId *NeighborForwardingBit
FaceId = FACE-ID-TYPE TLV-LENGTH NonNegativeInteger
NeighborForwardingBit = NEIGHBOR-FORWARDING-BIT-TYPE TLV-LENGTH NonNegativeInteger

BIFT-VERSION-TYPE = 601
BIER-INDEX-TYPE = 602
BIFT-ENTRY-TYPE = 603
BIFT-NEIGHBOR-TYPE = 605
BFR-ID-TYPE = 607
NEXT-HOP-TYPE = 609
ENTRY-FORWARDING-BIT-TYPE = 611
NEIGHBOR-FORWARDING-BIT-TYPE = 613
FACE-ID-TYPE = 105
```

BiftVersion is 1. BierIndex is omitted when BIER is disabled; zero is a valid
index. Name identifies the router, and NextHop contains a face ID. Forwarding
masks are encoded as repeated set-bit positions. These fields use the 600 series.

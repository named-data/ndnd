# BIER in NDNd

BIER (Bit Index Explicit Replication) provides stateless multicast forwarding for interests in NDNd.
Multicast forwarding for interests is primarily used for svs sync, either at the application level or by the routers to agree upon routing state.
Without BIER, multicast is still supported, but the interest will flood the network as a fallback (ideally, this is only used for routing state agreement).

Each router that participates in BIER also needs a unique BIER bit index configured in the forwarder YAML under `fw.bier_index` (defaulting to `-1` for routers lacking BIER support), for example:

```yaml
fw:
  bier_index: 3
```

Currently, on each router in a BIER-enabled network, operator must run `ndnd fw bift-register prefix=<router-name> index=<bfr-id>` for every `(router-name, bfr-id)` that exists in the network, then build the BIFT (BIER state representing forwarding trees) using `ndnd fw bift-rebuild`

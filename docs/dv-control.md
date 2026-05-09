# DV Control Reference

This is the detailed reference for the ndn-dv routing daemon control tool.

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

## `ndnd dv prefix-announce`

The `prefix-announce` command injects a local entry directly into the DV prefix state.
`expires=<milliseconds>` is optional and defines the validity period duration.
If omitted, the CLI sends `expires=3600000` (1 hour) in the management Interest.
`face` and `cost` are not carried in `prefix-announce` params.

```bash
# Announce /example for 60 seconds
ndnd dv prefix-announce prefix=/example expires=60000

# Announce /example with default 1 hour validity
ndnd dv prefix-announce prefix=/example
```

## `ndnd dv prefix-withdraw`

The `prefix-withdraw` command removes a local prefix entry from the DV prefix state.
`face` and `cost` are not part of `prefix-withdraw` params.

```bash
# Withdraw /example
ndnd dv prefix-withdraw prefix=/example
```

## `ndnd dv prefix-list`

The `prefix-list` command prints the local view of the DV prefix state database (PSD), including any validity window and remaining time before expiration.

```bash
# Show prefix list
ndnd dv prefix-list
```

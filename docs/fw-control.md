# Forwarder Control Reference

This is the detailed reference for the NDNd forwarder control tool, and implements the NFD Management Protocol.

You can also use the [nfdc](https://docs.named-data.net/NFD/24.07/manpages/nfdc.html) tool from the NFD project to manage the NDNd forwarder.

## `ndnd fw status`

The status command shows general status of the forwarder, including its version, uptime, data structure counters, and global packet counters.

## `ndnd fw face-list`

The face list command prints the face table, which contains information about faces.

## `ndnd fw face-create`

The face-create command creates a new face. The supported arguments are:

- `remote=<uri>`: The remote URI of the face.
- `local=<uri>`: The local URI of the face.
- `cost=<cost>`: The cost of the face.
- `persistency=<persistency>`: The persistency of the face (`persistent` or `permanent`).
- `mtu=<mtu>`: The MTU of the face in bytes.

```bash
# Create a UDP face with the default port
ndnd fw face-create remote=udp://suns.cs.ucla.edu

# Create a TCP face over IPv4
ndnd fw face-create remote=tcp4://suns.cs.ucla.edu:6363

# Create a peramanent TCP face with a cost of 10
ndnd fw face-create remote=tcp://suns.cs.ucla.edu cost=10 persistency=permanent
```

## `ndnd fw face-destroy`

The face-destroy command destroys a face. The supported arguments are:

- `face=<face-id>|<face-uri>`: The face ID or remote URI of the face to destroy.

```bash
# Destroy a face by ID
ndnd fw face-destroy face=6

# Destroy a face by remote URI
ndnd fw face-destroy face=tcp://suns.cs.ucla.edu
```

## `ndnd fw route-list`

The route-list command prints the existing RIB routes.

## `ndnd fw route-add`

The route-add command adds a route to the RIB. The supported arguments are:

- `prefix=<prefix>`: The name prefix of the route.
- `face=<face-id>|<face-uri>`: The next hop face ID to forward packets to.
- `cost=<cost>`: The cost of the route.
- `origin=<origin>`: The origin of the route (default=255).
- `expires=<expires>`: The expiration time of the route in milliseconds.

If a face URI is specified and the face does not exist, it will be created.

```bash
# Add a route to forward packets to a new or existing UDP face
ndnd fw route-add prefix=/ndn face=udp://suns.cs.ucla.edu

# Add a route with a permanent TCP face (face options must appear before "face=")
ndnd fw route-add prefix=/ndn persistency=permanent face=tcp://suns.cs.ucla.edu

# Add a route to forward packets to face 6
ndnd fw route-add prefix=/example face=6

# Add a route with a cost of 10 and origin of "client"
ndnd fw route-add prefix=/example face=6 cost=10 origin=65
```

## `ndnd fw route-remove`

The route-remove command removes a route from the RIB. The supported arguments are:

- `prefix=<prefix>`: The name prefix of the route.
- `face=<face-id>|<face-uri>`: The next hop face ID of the route.
- `origin=<origin>`: The origin of the route (default=255).

```bash
# Remove a route by prefix, face and origin
ndnd fw route-remove prefix=/example face=6 origin=65
```

## `ndnd fw fib-list`

The fib-list command prints the existing FIB entries.

## `ndnd fw pib-list`

The pib-list command prints the existing PIB entries.

## `ndnd fw pib-add-egress`

The pib-add-prefix command adds an egress router to a PIB entry. The supported arguments are:

- `prefix=<prefix>` The name prefix of the PIB entry.
- `egress=<egress-name>` The egress name

```bash
./ndnd fw pib-add-egress prefix=/example egress=/egress-name
```

## `ndnd fw pib-remove-egress`

The pib-add-prefix command removes an egress router to a PIB entry. The supported arguments are:

- `prefix=<prefix>` The name prefix of the PIB entry.
- `egress=<egress-name>` The egress name

```bash
./ndnd fw pib-remove-egress prefix=/example egress=/egress-name
```

## `ndnd fw pib-add-nexthop`

The pib-add-nexthop command adds a next hop to a PIB entry (for local forwarding). The supported arguments are:

- `prefix=<prefix>`: The name prefix of the PIB entry.
- `face=<face-id>|<face-uri>`: The next hop face ID to add (must be a valid face).

```bash
ndnd fw pib-add-nexthop prefix=/example face=6
```

## `ndnd fw pib-remove-nexthop`

The pib-remove-nexthop command removes a nexthop from a PIB entry. The supported arguments are:

- `prefix=<prefix>`: The name prefix of the PIB entry.
- `face=<face-id>|<face-uri>`: The next hop face ID to remove.

```bash
ndnd fw pib-remove-nexthop prefix=/example face=6
```

## `ndnd fw cs-info`

The cs-info command prints information about the content store.

## `ndnd fw strategy-list`

The strategy-list command prints the currently selected forwarding strategies.

## `ndnd fw strategy-set`

The strategy-set command sets a forwarding strategy for a name prefix. The supported arguments are:

- `prefix=<prefix>`: The name prefix to set the strategy for.
- `strategy=<strategy>`: The forwarding strategy to set.

```bash
# Set the strategy for /example to "multicast"
ndnd fw strategy-set prefix=/example strategy=/localhost/nfd/strategy/multicast/v=1

# Set the strategy for /example to "best-route"
ndnd fw strategy-set prefix=/example strategy=/localhost/nfd/strategy/best-route/v=1
```

## `ndnd fw strategy-unset`

The strategy-unset command unsets a forwarding strategy for a name prefix. The supported arguments are:

- `prefix=<prefix>`: The name prefix to unset the strategy for.

```bash
# Unset the strategy for /example
ndnd fw strategy-unset prefix=/example
```

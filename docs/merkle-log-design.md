# Merkle History Log Protocol and Expired-Certificate Policy

Status: Experimental Design Specification

Design revision: 1 (not encoded on the wire)

This specification describes the current [log service](../merkle/api.go),
[Merkle core and client](../std/merklelog/),
[wire models](../std/ndn/merklelog/definitions.go), and
[trust validator](../std/security/trust_config.go). Implementation limits are
called out below; the auditor model remains future work.

## Abstract

An expired certificate does not necessarily make every packet signed by its
key unusable. A consumer can validate historical Data if it has trustworthy
evidence that the exact packet existed while its signing certificate was
valid.

The Merkle history log records SHA-256 hashes of complete Data packets as
encoded on the wire. An authorized requester explicitly submits hashes; the
log assigns an ingestion time and commits them to an append-only Merkle tree.
A consumer later retrieves a signed root and inclusion proof. An asynchronous
history policy accepts an expired validation relation only when the current
packet was logged within the authorizing certificate's validity period.
Normal trust-schema and signature validation still applies.

This revision trusts one log operator. It does not provide consistency proofs,
witnesses, gossip, or protection against equivocation by that operator.

## 1. Scope and system model

This revision provides:

- explicit authenticated submission of one or more packet hashes;
- one log-assigned timestamp and at most one leaf per append request;
- first-ingestion semantics for duplicate hashes;
- a durable Merkle tree and hash-to-leaf index;
- public single-hash checks with signed, possibly segmented responses; and
- an asynchronous expiry policy that works through certificate recursion.

It does not discover packets automatically, retrieve packets represented by
submitted hashes, prove that the log clock is honest, or provide a
cryptographic non-inclusion proof.

```text
                  explicit submission
 +------------------+   signed command    +----------------------+
 | Append requester | ------------------> | Merkle log           |
 | hashes exact wire|                     |                      |
 +------------------+   public check      |                      |
 | Data consumer    | ------------------> |                      |
 | + trust policy   | <------------------ |  +----------------+  |
 | + expiry policy  |  signed proof object|  | Merkle tree    |  |
 +------------------+                     |  +----------------+  |
                                          +----------------------+
```

The requester computes hashes from the exact packet wire. The log
authenticates requesters, assigns ingestion times, atomically extends the
tree, and signs responses. Consumers authenticate responses and verify proofs
under their configured trust policy. The application chooses the expiry
policy and any larger operation deadline.

The log receives hashes rather than packets, so it cannot prove that the
corresponding bytes were observed. Authentication only binds a submission to
an authorized requester; the admission policy decides whose observation
claims to trust.

## 2. Packet and tree model

### 2.1. Exact packet identity

For complete Data wire `W`:

```text
DataHash = SHA256(W)
```

`W` includes the outer Data TLV, Name, MetaInfo, Content, SignatureInfo, and
SignatureValue exactly as encoded. Certificates are Data packets and use the
same calculation. This is the digest used by an NDN
ImplicitSha256DigestComponent, although this protocol transports it as a
generic name component and in `DataHash` TLVs.

Hashing only Content, only signature-covered wire, or a re-encoded parsed Data
packet is invalid. Re-encoding MUST NOT be assumed to reproduce the received
bytes. The validation interface MUST preserve the exact received Data wire;
missing exact wire MUST cause the history policy to reject.

### 2.2. Log entries and batching

One accepted append request creates at most one leaf:

```text
LogEntry = IngestTime 1*DataHash
```

Only the first occurrence of each new 32-byte hash is placed in the entry, in
request order. Existing hashes and later duplicates within the request MUST NOT
be inserted again.

Consequently, multiple hashes may share one leaf, timestamp, and leaf index:

```text
AppendRequest [H1, H2, H3]
             |
             v
Leaf 7 = LogEntry(Time, H1, H2, H3)
```

A check for any of those hashes returns the complete `LogEntry`, including the
other hashes. Batching therefore reduces leaf count but exposes which hashes
were submitted together.

`IngestTime` is an integer count of whole milliseconds since the Unix epoch in
the inclusive range 0 through 9,223,372,036,854. Sub-millisecond values are
invalid. The on-the-wire encoding is a big-endian NDN non-negative integer,
using the shortest permitted width (1, 2, 4, or 8 bytes) that represents the
value.

### 2.3. Hashing and tree shape

```text
LeafHash(E) = SHA256(0x00 || CompleteLogEntryTLV(E))
NodeHash(L, R) = SHA256(0x01 || L || R)
EmptyRoot = SHA256(empty byte string)
```

The domain bytes distinguish leaves from interior nodes. The complete leaf
input includes the `LogEntry` TLV with type `0x1E12`, its canonical length,
and its raw TLV-VALUE. A proof carries the unmodified TLV-VALUE; the verifier
MUST restore the fixed outer type and canonical length before hashing.

The tree accepts only complete entries matching their canonical encoding: one
`IngestTime` followed by the ordered `DataHash` TLVs, with canonical type,
length, and integer encodings. The proof verifier applies the same check after
restoring the outer wrapper, so the preserved TLV-VALUE must be canonical too.
Reordered fields, additional fields, repeated `IngestTime`, or non-canonical
inner encodings are rejected. Canonicality is checked by comparison with a
re-encoding; the hash input retains the received entry value.

For more than one leaf, the split point is the largest power of two strictly
smaller than the leaf count. For five leaves:

```text
                         Root
                       /      \
                    N(0..3)    L4
                   /      \
                N(0..1)  N(2..3)
                /   \     /   \
               L0   L1   L2   L3
```

Leaves MUST be zero-indexed. Sibling hashes are ordered from the leaf upward.
The path for `L2` above is `[L3, N(0..1), L4]`. The verifier MUST derive
left/right placement from `LeafIndex` and `TreeSize`, and MUST reject missing
or extra siblings, invalid lengths, out-of-range indexes, and root mismatches.

### 2.4. Time and complexity

The log assigns each new leaf the current Unix time truncated to milliseconds,
or the last committed ingestion time plus one millisecond, whichever is later.
The tree MUST reject an entry whose time is not strictly later than its
predecessor's. The last committed time is restored on restart. An append that
fails before committing does not reserve a timestamp; a later attempt may
reuse that candidate time. Monotonicity therefore applies to committed leaves
and does not make the clock trustworthy or bound its drift from wall time.

For `N` leaves and `B` hashes in the proven entry, incremental root calculation
uses `O(log N)` tree-hash work. The sibling path contains `O(log N)` hashes,
but the proof also carries the entire entry: total proof size and verification
work are `O(B + log N)`. The current implementation keeps entries, leaf hashes,
and the hash index in memory. It generates a proof by recomputing sibling
subtrees from leaf hashes, requiring `O(N)` hash work per proof.

## 3. TLV wire format

### 3.1. Assigned types

```text
Type name          Hex       Decimal
------------------------------------
DataHash           0x1E00       7680
AppendResult       0x1E02       7682
Status             0x1E04       7684
LeafIndex          0x1E06       7686
TreeRoot           0x1E08       7688
CheckResult        0x1E0A       7690
InclusionProof     0x1E0C       7692
TreeSize           0x1E0E       7694
RootHash           0x1E10       7696
LogEntry           0x1E12       7698
SiblingHash        0x1E14       7700
IngestTime         0x1E16       7702
```

Append request, append response, and check response are content models without
additional outer wrapper TLVs.

### 3.2. Grammar

```text
AppendRequest  = 1*DataHash

AppendResponse = 1*AppendResult
AppendResult   = DataHash Status [LeafIndex]

CheckResponse  = TreeRoot CheckResult
TreeRoot       = TreeSize RootHash
CheckResult    = DataHash Status [InclusionProof]
InclusionProof = LogEntry LeafIndex *SiblingHash

LogEntry       = IngestTime 1*DataHash
```

Valid hashes are 32 bytes. An append result with status `FAILED` can echo a
request's invalid-length `DataHash` as described in Section 4. `TreeSize`,
`LeafIndex`, and `Status` are unsigned NDN non-negative integers; the encoder
uses the shortest permitted width of 1, 2, 4, or 8 bytes.

Append status values and invariants are:

```text
Value  Name       LeafIndex       Meaning
----------------------------------------------------------
0      OK         REQUIRED        hash was placed in a new leaf
1      DUPLICATE  REQUIRED        hash was already logged, including earlier
                                 in this request
2      FAILED     MUST be absent  hash was not appended
```

Check status values are:

```text
Value  Name       InclusionProof
--------------------------------
0      INCLUDED   REQUIRED
1      NOT_FOUND  MUST be absent
```

The response `DataHash` MUST equal the request. `NOT_FOUND` is a signed log
statement for that root, not a Merkle non-inclusion proof or a statement about
future roots.

### 3.3. Protocol names

Let `P` be the log prefix. `append` and `check` are keyword components of type
32. A queried hash is a generic component of type 8.

```text
Append command prefix:
  P / 32=append

Embedded signed AppendRequest Data name:
  P / 32=append / <requester-name-components> / t=<unix-ms>

Append Interest name:
  P / 32=append / params-sha256=<application-parameters-digest>

Check Interest name:
  P / 32=check / 8=<32-byte-DataHash>

Check object and segments:
  P / 32=check / 8=<DataHash> / v=<TreeSize>
  P / 32=check / 8=<DataHash> / v=<TreeSize> / seg=<n>
```

The append Interest application parameters contain the complete signed request
Data. NDN encoding adds the ParametersSha256DigestComponent; the log MUST NOT
require a second request digest. Append response Data uses the complete
Interest name. A check object version MUST equal its `TreeSize`.

## 4. Append protocol

```text
Requester                                       Merkle log
        |                                           |
        | hash exact packet wire                    |
        | build and sign AppendRequest Data         |
        |-- Interest + application parameters ----->|
        |                                           | authenticate request
        |                                           | validate name/time
        |                                           | classify hashes
        |                                           | persist one update
        |<--------- signed AppendResponse -----------|
        | validate signature and result fields      |
```

The log authenticates the complete embedded request Data under its configured
trust policy. The request Data name MUST:

1. begin with `P/32=append`;
2. contain at least one requester-name component; and
3. end in a canonical timestamp within one minute of log time.

The timestamp is a freshness check, not replay prevention. The log MUST NOT
use it as `IngestTime`.

An append command that fails authentication, has unparsable content, has a
malformed name, has a timestamp outside the freshness window, or contains zero
`DataHash` TLVs MUST receive no response. The log MUST NOT partially process
such a command. A parseable `DataHash` TLV whose value is not 32 bytes is an
invalid item rather than a malformed command and receives `FAILED` below.

For each requested hash, the log reports:

- `FAILED` for a non-32-byte value;
- `DUPLICATE` and the existing leaf for a hash already in the log;
- `OK` for the first occurrence of each previously-unseen hash; or
- `DUPLICATE` with the new leaf index for a later occurrence within the same
  request of a hash that was `OK` earlier in the same request.

If any new hashes remain after classification, they form one `LogEntry` and
one atomic tree update. Every `OK` result and every within-request
later-occurrence receives that new leaf index. If persistence fails, results
dependent on the new entry become `FAILED`; pre-existing duplicates remain
`DUPLICATE`. If nothing is new, no leaf or `IngestTime` is created. Results
remain in request order.

The client validates the signed response, result count, corresponding hashes,
status values, `LeafIndex` presence for `OK` and `DUPLICATE`, and its absence
for `FAILED`. The supplied client rejects empty submissions and invalid-length
hashes locally, before sending a command. Append responses contain no root or
proof.

Append requests and responses are not segmented. Their fully encoded Interest
and Data packets MUST NOT exceed the 8,800-byte maximum NDN packet size. The
current Merkle client and command handler do not preflight those sizes or split
batches automatically; oversized-packet handling depends on the transport. A
requester MUST allow for both request and response overhead and split a larger
submission into multiple commands, each becoming a separate batching and
timestamp boundary. The append commits before the response is encoded and
sent, so a response failure does not roll back the append. Retrying a newly
signed command is safe because hashes have first-ingestion semantics. The
append client performs no automatic retries. Check responses use segmentation
as described below.

## 5. Check protocol

```text
Consumer/expiry policy                         Merkle log
        |                                           |
        |-- Interest P/32=check/8=<hash> ---------->|
        |    CanBePrefix=true, MustBeFresh=true     |
        |                                           | snapshot root
        |                                           | lookup hash -> leaf
        |                                           | build proof/status
        |<-- .../<hash>/v=<size>/seg=0 -------------|
        |-- additional segment Interests ---------->|
        |<-- signed segments ------------------------|
        | validate, assemble, parse, verify          |
```

The initial Interest contains exactly one generic 32-byte hash after
`P/32=check` and sets `CanBePrefix` and `MustBeFresh`. The service requires
`CanBePrefix` for this name shape but does not enforce `MustBeFresh`. Exact
names ending in version and segment are used to retrieve already-produced
segments. Other shapes receive no response.

The log evaluates each check against one atomic tree snapshot and resolves the
requested hash to its first leaf index. If present, it returns the complete
leaf `LogEntry`, its index, and the sibling path. Otherwise it returns
`NOT_FOUND` with the snapshot root. Multiple hashes from one append may map to
the same leaf.

The response is a metadata-free, standard NDN segmented object. Every segment
MUST be signed and authenticated, and all segments MUST represent the same
tree snapshot. An unversioned query that reaches the service uses the tree
size at the time the service takes its snapshot.

The service uses the Object producer's default four-second `FreshnessPeriod`
and reuses stored segments for an already-produced hash/version pair. A fresh
cached response may satisfy an unversioned Interest even after the tree has
grown. `MustBeFresh` does not guarantee the latest tree size or establish a
checkpoint age. The client verifies the returned snapshot but does not track
previously observed roots or enforce a minimum tree size.

For an empty tree (`TreeSize = 0`), every check returns `NOT_FOUND` with the
empty-tree root. A versioned segment Interest whose `TreeSize` is no longer
available, or whose segment number is past the last segment, MUST receive no
response. Versioned requests only look up cached segments; they do not generate
proofs for arbitrary historical tree sizes. Previously produced segments can
remain available after the tree grows or the service restarts.

Before succeeding, the client MUST:

1. validate Object Data signatures under the log trust configuration;
2. parse the response content and confirm a 32-byte root;
3. confirm the object version equals `TreeSize`;
4. confirm the returned hash equals the requested hash;
5. confirm a known status with correct proof presence; and
6. validate the inclusion proof for `INCLUDED`.

For an empty tree, the root MUST equal `SHA256("")`.

## 6. Persistence

The service stores ordered entries, the hash-to-first-leaf mapping, tree size,
root, frontier, and last ingestion time in a dedicated Badger database with
synchronous writes. Each append updates these records in one transaction.
Only after the store reports success does the in-memory tree advance. The
service serializes appends and check snapshots with one mutex, so a snapshot
contains either the complete state before an append or the complete state
after it.

On opening the tree, the implementation replays all entries and compares the
reconstructed state and hash index with the persisted records. Non-contiguous
leaves, duplicate hashes, non-increasing ingestion times, invalid indexes, or
inconsistent root, frontier, or last ingestion time cause startup to fail.

Each store append checks the expected tree size, stored frontier/root state,
new entry, and affected index records. A rejected write leaves the in-memory
tree unchanged. This is not a continuous integrity audit: checks and duplicate
lookups use the in-memory tree without rereading the database. A store error
does not disable subsequent reads or automatically reload the tree. The
service assumes a single writer and an atomic store with reliable commit
reporting; recovery from an ambiguous commit outcome is not implemented.

Signed check objects use a separate packet database. Their creation and
retention are independent of the log transaction; a committed leaf remains
committed even if producing or sending its response fails.

## 7. Expired-certificate integration

The asynchronous history policy requires the current Data, its exact received
wire, the authorizing certificate, and a complete ordered validity interval on
that certificate.

```text
H = SHA256(DataWire)
R = Check(H)

require R.Status == INCLUDED
require inclusion proof verifies H against R.Root
E = parse R.Proof.LogEntry
require Cert.NotBefore <= E.IngestTime <= Cert.NotAfter

complete(success)
```

Both validity endpoints are inclusive. The policy does not use the signer's
asserted `SignatureTime`. The response and proof are verified before the policy
evaluates ingestion time. Missing wire or evidence, invalid validity, retrieval
failure, response-signature failure, proof failure, and out-of-range time all
reject the relation.

The policy starts the check and completes asynchronously. The application MAY
bound the larger validation operation with a deadline.

### 7.1. Recursive validation

The validator invokes the policy when the authorizing certificate is outside
its validity period, when the current Data is itself a certificate outside its
validity period, or when an expired cross-schema packet is being recursively
validated. The implementation's expiry predicate also includes not-yet-valid
certificates and certificates with missing validity endpoints. The history
policy still requires the authorizer's complete, ordered validity interval.

For Data `D` signed by child certificate `C1`, itself signed by `C2`:

```text
             relation 1              relation 2
       D  <--------------  C1  <-----------------  C2
       |                    |
       |                    +-- Check(SHA256(wire(C1)))
       +-- Check(SHA256(wire(D)))
```

If `C1` is expired and is not already a trust anchor, successful recursive
validation requires two policy acceptances:

1. `Data=D, Cert=C1`: `D` MUST have been logged during `C1` validity.
2. `Data=C1, Cert=C2`: the exact `C1` packet MUST have been logged during `C2`
   validity.

Every affected packet-to-authorizer relation requires separate evidence. The
same contract applies to expired cross-schema relations: the current Data wire
is hashed and the authorizer's validity is applied.

After policy acceptance, the validator still checks the schema and packet
signature. A proof cannot authorize a forbidden signer or repair an invalid
signature.

### 7.2. Wire preservation and completion

Exact packet wire MUST remain associated with the packet through every step of
recursive validation and any intermediate storage. A non-anchor certificate
retained as evidence is not, by itself, a reusable validation decision; its
chain and expiry relation are revalidated each time the evidence is consumed.
An asynchronous policy MUST resolve each validation relation exactly once.
The validator resumes a relation only on the first completion; subsequent
completion calls are ignored. There is no built-in policy deadline.

### 7.3. Trust-anchor promotion

Use of the history policy does not prevent trust-anchor promotion. The current
trust validator promotes a self-signed anchor candidate after an authorized
`CertList` (see [certlist.md](certlist.md)) supplies a certificate with the same
key content and that certificate validates successfully, or is already a
trust anchor. The history policy itself does not perform the promotion.

If the listed certificate is expired, the `CertList` packet must also pass the
policy with `Data=CertList, Cert=listed certificate`. Its exact wire must have
been logged during the listed certificate's validity. Recursive validation of
the listed certificate applies any additional history checks. An expired
self-signed candidate also requires evidence for its own wire against its own
validity period before the validator explores the `CertList`.

Once promoted, the candidate is treated as a trust anchor in that trust
configuration. Later validations can terminate their chain at it without
revalidating the admitting `CertList` and listed certificate. Expiry checks for
the current packet-to-anchor relation still apply. Ordinary non-anchor
retention does not perform this promotion.

## 8. Trust and security considerations

Configured trust policies authorize append command Data and response-signing
identities. Consumers MUST authenticate log responses independently. The
history policy MUST NOT be used recursively to justify an expired log-response
signer through the same log. Supplying the independent response trust policy is
the consumer's responsibility; an accept-all validator does not conform to
this design.

The log operator is trusted to assign honest times and maintain one history. A
proof authenticates membership relative to a signed response root, but the
operator can still backdate entries, equivocate between clients, or lie in a
`NOT_FOUND` response. Independent checkpoints and auditors are needed to
address those threats.

The policy supplements normal validation; it does not replace schema,
key-locator, certificate-chain, or signature checks. Its packet binding relies
on SHA-256 and on the caller supplying exact wire that actually corresponds to
the parsed Data and signature-covered wire.

This revision defines no append rate limit, tree-pruning policy, or
check-response retention duration. Deployments require admission and resource
controls.

Unauthenticated commands, unparsable command content, invalid command names,
empty append requests, and malformed check names MUST receive no response.
Parseable append requests containing a `DataHash` with an invalid length
receive a per-item `FAILED` result. Clients MUST reject malformed, mismatched,
unsigned, untrusted, or cryptographically invalid responses. There is no
machine-readable protocol error object in this revision.

## 9. Auditor model (Discussion)

Status: discussion only. This section is non-normative and outside the current
design.

A stateless consumer cannot determine whether the log has rewritten history or
shown different roots to different clients. A possible future model assigns
that work to independent, stateful auditors:

```text
 +------------------+    signed append     +------------------+
 | Append requester | -------------------> | Merkle log       |
 +------------------+                      +------------------+
          |                                      | entries,
          | verify own inclusion                 | checkpoints
          v                                      v
 +------------------+    approved root     +------------------+
 | Data consumer    | <------------------- | Auditor(s)       |
 | + expiry policy  |                      | retained history |
 +------------------+                      +------------------+
                                                   |
                                                   | gossip
                                                   v
                                            +------------------+
                                            | Other auditors   |
                                            | or witnesses     |
                                            +------------------+
```

The policies remain distinct:

- Log admission policy: who may append and which key signs responses.
- Auditor policy: whether log transitions are append-only, timely, and
  consistent with previously accepted state.
- Consumer history policy: whether approved evidence permits one expired
  validation relation.

A future signed checkpoint might contain:

```text
LogCheckpoint {
    LogName
    TreeSize
    RootHash
    CheckpointTime
    LastIngestTime
}
```

Given an authenticated entry stream, an auditor could verify the log signature,
stable roots at repeated sizes, a consistency proof from its prior root,
canonical new entries, unique hashes, strictly increasing ingestion times, and
configured clock-skew limits. It could then sign an approval for the
checkpoint. Conflicting signed states would be retained and reported rather
than silently replaced.

A consumer could require an exact proof root approved by one auditor or a
`k-of-n` quorum, subject to maximum approval age and clock-skew policy:

```text
exact packet hash + inclusion proof + approved root + valid ingestion time
                  + normal schema and signature validation
```

Append requesters can separately monitor inclusion of their own submissions,
but cannot detect a split view without gossip.

This model would require signed checkpoint publication, consistency proofs,
entry retrieval by index or incremental feed, approval encoding, gossip, a
minimum-age requirement on checkpoint acceptance, and checks against a
specified tree size. This revision's unversioned `Check` takes a current
snapshot when it reaches the service, but caches may return an earlier
snapshot. It does not support generating a proof at a caller-selected tree
size. An auditor retrieving entries would also see every hash in each batched
leaf.

## 10. Open design issues

Deferred work includes:

1. a proactive append batch bound that accounts for response-signing overhead;
2. signed checkpoints and consistency proofs;
3. auditor or witness approvals and gossip;
4. cryptographic or independently verifiable non-inclusion;
5. configurable requester retries and recovery from ambiguous commit outcomes;
6. scalable proof generation;
7. check-response retention and garbage collection;
8. explicit version negotiation and stable type allocation;
9. checkpoint freshness and minimum-tree-size requirements; and
10. continuous store-integrity auditing and service behaviour after store errors.

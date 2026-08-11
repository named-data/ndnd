# State Vector Sync (SVS) v4 Specification

SVS v4 is a state-vector synchronization protocol for large sync groups.
It introduces a membership hash (`mhash`), two direct state-vector
encodings (`FULL` and `PARTIAL`) carried as distinct TLVs, and a third
publish-only form that references a retrievable full vector. Every Sync
Data carries `mhash` and one of `FullStateVector`, `PartialStateVector`,
or `SvsDataRef`.

---

## 1. Basic Protocol Design

### 1.1 Small groups

For most deployments, the complete State Vector fits in one Sync packet.
Nodes exchange **full** State Vectors using steady-state, suppression, merge,
and `OnUpdate` semantics.

### 1.2 Large groups

When the encoded State Vector exceeds **`SyncVectorThreshold`** (a
fixed library constant of 1200 bytes), nodes use three dissemination
modes:

| Mode | Trigger | Wire shape |
|------|---------|------------|
| **Direct FULL** | Encoded FULL fits in threshold | `FullStateVector` (`mhash` + complete `StateVector`) in Sync Data |
| **Direct PARTIAL** | New publication and FULL exceeds threshold | `PartialStateVector` (`mhash` + subset `StateVector`) in Sync Data |
| **Referenced FULL** | Periodic sync (large group), or `mhash` mismatch | Produce full vector Data at `32=sv/<version>`; Sync Data carries only `SvsDataRef` |

`mhash` is defined in §3.3.

**Full state recovery** uses publish + pull when:

1. `mhash` differs from the local membership hash, or
2. Periodic sync runs while the local FULL encoding exceeds
   `SyncVectorThreshold`, or
3. A direct `FullStateVector` is outdated per §6.2.

Retrievable full-vector Data uses the standard NDN segmentation convention
when it exceeds a single packet.

---

## 2. Format and Naming

### 2.1 Sync Interest

**Sync Interest Name:**

```
/<sync-prefix>/v=4
```

Implementations MAY append additional name components after `v=4`. The
Interest nonce is carried in Interest packet fields, not as a name component.

- Signed Sync Data is carried in `ApplicationParameters`.
- Interest Lifetime is 1 second.
- Sync Interests are unacknowledged.

### 2.2 Sync Data (in ApplicationParameters)

**Sync Data Name** (signing identity for the Sync message):

```
/<group>/<node>/<boot time>/<version>
```

- **`version`:** microsecond timestamp. No hash suffix is used.

**Sync Data Content:** encoded `SvsData` (§3) — either direct form (FULL
or PARTIAL) or publish-only form.

### 2.3 Application publication Data

```
/<group>/<node>/<boot time>/seq=<n>
```

Application-level naming may vary. Sync vector Data lives in a separate
namespace distinguished by the `32=sv` keyword (§2.4).

### 2.4 Published full State Vector Data

Retrievable full State Vector objects use a dedicated sync namespace:

**Name:**

```
/<group>/<node>/<boot time>/32=sv/<version>
```

**Content:** signed `SvsData` in direct FULL form: `FullStateVector`
containing `mhash` and complete `StateVector`.

**Publish + pull procedure** (periodic sync, `mhash` recovery, join when
FULL exceeds threshold):

1. Produce the full-vector Data at
   `/<group>/<node>/<boot>/32=sv/<version>`. The data is segmented
   per the standard NDN convention if it does not fit in a single packet.
2. Send a Sync Interest whose AppParam Sync Data contains publish-only
   `SvsData`: `mhash` + `SvsDataRef` pointing at the published name (§3.1).
3. Receivers pull the referenced Data, validate, and merge.

A Sync message carries either a direct StateVector or a publish-only
reference — not both.

---

## 3. Packet Specification

### 3.1 `SvsData`

`SvsData` is a tagged union. The wire carries:

- `MemberSetHash` (`0xCB`): 32-byte `mhash`, present in all three forms.
- One of the following three top-level TLVs (the choice replaces the
  previous `VectorType` discriminator):
  - `FullStateVector` (`0xCD`): direct form with a complete State Vector.
  - `PartialStateVector` (`0xCE`): direct form with a publication-time
    subset.
  - `SvsDataRef` (`0x07`): publish-only form pointing to a retrievable
    full-vector Data.

```
SvsData = SVS-DATA-TYPE TLV-LENGTH
          MemberSetHash                ; always present
          ( FullStateVector
          | PartialStateVector
          | SvsDataRef )               ; exactly one

FullStateVector    = FULL-STATE-VECTOR-TYPE    TLV-LENGTH StateVector
PartialStateVector = PARTIAL-STATE-VECTOR-TYPE TLV-LENGTH StateVector
```

| Field | TLV type | Value |
|-------|----------|-------|
| `MemberSetHash` | `0xCB` | 32-byte SHA-256 digest (`mhash`) |
| `FullStateVector` | `0xCD` | Complete `StateVector` (§3.2) |
| `PartialStateVector` | `0xCE` | Subset `StateVector` (§3.2) |
| `SvsDataRef` | `0x07` (Name) | Name of the published full-vector Data. The receiver strips the trailing version component and uses the resulting `32=sv` prefix as the trust anchor for that sender's retrievable full vectors. |

The receiver MUST reject Sync Data that carries both `FullStateVector`
and `PartialStateVector`, and Sync Data that carries none of the three.
`mhash` MUST be exactly 32 bytes when present.

### 3.2 `StateVector`

```
StateVector = STATE-VECTOR-TYPE TLV-LENGTH
              *StateVectorEntry

StateVectorEntry = STATE-VECTOR-ENTRY-TYPE TLV-LENGTH
                   Name
                   *SeqNoEntry

SeqNoEntry = SEQ-NO-ENTRY-TYPE TLV-LENGTH
             BootstrapTime
             SeqNo
```

| TLV | Type (decimal) | Type (hex) |
|-----|----------------|------------|
| `FULL-STATE-VECTOR-TYPE` | 205 | `0xCD` |
| `PARTIAL-STATE-VECTOR-TYPE` | 206 | `0xCE` |
| `STATE-VECTOR-TYPE` | 201 | `0xC9` |
| `STATE-VECTOR-ENTRY-TYPE` | 202 | `0xCA` |
| `SEQ-NO-ENTRY-TYPE` | 210 | `0xD2` |
| `BOOTSTRAP-TIME-TYPE` | 212 | `0xD4` |
| `SEQ-NO-TYPE` | 214 | `0xD6` |

**Rules:**

- Sequence numbers are 1-indexed.
- Bootstrap time is seconds since Unix epoch.
- A missing entry compares as `SeqNo = 0` against a present entry.
- Reject the entire `StateVector` if any received `BootstrapTime` is more
  than 86400s in the future.

### 3.3 `MemberSetHash` (`mhash`)

`mhash` is a **membership hash**: the SHA-256 digest of the membership set
described below. Membership is independent of sequence numbers, so `mhash`
is unaffected by data publications within the group.

**Membership** is the set of participants, each identified by:

```
(Producer Name, Bootstrap Time)
```

**Computation:**

```
members = { (Name, BootstrapTime) | node knows this member in the sync group }
sort by NDN canonical order of Name, then by BootstrapTime ascending
mhash = SHA-256( concatenation of canonical TLV bytes of each (Name, BootstrapTime) pair )
```

Recompute `mhash` whenever membership changes (member added, removed, or new
bootstrap time for a name).

The full State Vector carries membership implicitly: every member's
`StateVectorEntry` is present with its current sequence number. `mhash`
summarizes that membership for quick comparison without having to walk the
full State Vector.

### 3.4 `FullStateVector` vs. `PartialStateVector`

The wire TLV itself disambiguates the direct form:

| TLV | Name | Meaning |
|-----|------|---------|
| `0xCD` | **FULL** | `StateVector` contains the complete advertised state (§4.1 ordering). |
| `0xCE` | **PARTIAL** | `StateVector` contains a subset (§4.2). Used for new publication only when FULL exceeds threshold. |

Distinct TLVs (instead of a shared field with a discriminator) let a
receiver skip the more expensive subset-evaluation code path when it sees
`FullStateVector`, and let a sender guarantee the receiver knows whether
missing names imply partition (FULL) or merely "not included in this
subset" (PARTIAL). `mhash` alone cannot convey this — two parties with
identical membership but different subscription views may legitimately
disagree on what subset was sent.

The publish-only form (`SvsDataRef` only, no embedded `StateVector`)
carries neither TLV; the receiver treats it as a signal to fetch the
referenced full vector.

---

## 4. State Vector Encoding

### 4.1 FULL State Vector

- Include all known members and their latest sequence numbers per bootstrap.
- Entries ordered in NDN canonical order of `Name`.
- Wire TLV is `FullStateVector` (`0xCD`, §3.4).

### 4.2 PARTIAL State Vector

Used on new publication when
`encoded_size(direct FULL SvsData) > SyncVectorThreshold`.

- Wire TLV is `PartialStateVector` (`0xCE`, §3.4).
- The first entry is the sender's own `StateVectorEntry`; the sender is
  always included.
- The remaining entries are the sender's selected peers, ordered in NDN
  canonical name order.

If the sender-only baseline already exceeds `SyncVectorThreshold`, the
sender falls back to publish + pull. The implementation MAY emit an empty
PARTIAL in this case as a signal to the caller; the caller MUST treat an
empty PARTIAL as the publish + pull trigger instead of forwarding it.

An implementation MAY use the following selection priority:

| Priority | Include |
|----------|---------|
| 1 | Sender (always) |
| 2 | Repair targets |
| 3 | Propagation targets |
| 4 | Random inactive producers |
| 5 | Others by recency |

Stop adding entries when the estimated direct `SvsData` size approaches
`SyncVectorThreshold`.

### 4.3 `SyncVectorThreshold`

`SyncVectorThreshold` is a fixed library constant (1200 bytes) that bounds
the size of a direct SvsData:

- When `encoded_size(FULL) ≤ SyncVectorThreshold`, nodes use direct FULL
  (`FullStateVector`).
- When `encoded_size(FULL) > SyncVectorThreshold`, nodes switch to PARTIAL
  (`PartialStateVector`, on publication) or publish + pull (`SvsDataRef`,
  on periodic sync and recovery).

The wire format is independent of `SyncVectorThreshold`. Every Sync
message carries exactly one of `FullStateVector`, `PartialStateVector`,
or `SvsDataRef`.

---

## 5. State Sync

Sections 5.1–5.4 describe the steady-state sync loop. Sections 5.5–5.9
describe the large-group paths.

### 5.1 Sync Interest timer

- `PeriodicTimeout` default 30s (±10% jitter).
- `SuppressionPeriod` default 200ms.
- `SuppressionTimeout` exponential decay.

### 5.2 Send Sync Interest on new publication

When the node generates a new publication, it immediately emits a Sync
Interest and resets the timer to `PeriodicTimeout`.

| Trigger | Action |
|---------|--------|
| `encoded_size(direct FULL) ≤ SyncVectorThreshold` | Send direct FULL (`FullStateVector` with `mhash` + `StateVector`) |
| `encoded_size(direct FULL) > SyncVectorThreshold` | Send direct PARTIAL (`PartialStateVector` with `mhash` + subset `StateVector`), or publish + pull if the sender-only baseline itself exceeds the threshold |

### 5.3 Sync Ack policy

Sync Interests are unacknowledged.

### 5.4 Steady state and suppression (direct FULL)

For incoming Sync Data carrying `FullStateVector`, apply the
steady-state and suppression rules in §5.1–§5.4.

### 5.5 PARTIAL State Vector processing

When the wire carries `PartialStateVector`:

1. Parse `mhash` and `StateVector`.
2. Names omitted from the partial `StateVector` are interpreted as "not
   included in this subset" — they do not imply producer removal, outdated
   sender, or sequence rollback.
3. For each present entry, merge newer sequence numbers into local state
   (§6.1).
4. If `mhash` differs from local `mhash`, perform publish + pull recovery
   (§5.6).

PARTIAL processing is the only receive-side change relative to the
direct-FULL path.

### 5.6 Full state recovery (publish + pull)

**Triggers:**

| # | Trigger | Action |
|---|---------|--------|
| 1 | `mhash` in received `SvsData` ≠ locally computed `mhash` | Publish + pull |
| 2 | Direct `FullStateVector` is outdated per §6.2 | Merge direct if complete; otherwise publish + pull |
| 3 | Periodic sync while local FULL exceeds `SyncVectorThreshold` | Publish + pull (§5.8) |

Recovery always fetches the complete State Vector from the referenced
`32=sv/<version>` Data.

**Sender procedure** (on `mhash` mismatch or periodic large-group sync):

1. Produce full-vector Data at `/<group>/<sender>/<boot>/32=sv/<version>`
   with `FullStateVector` SvsData.
2. Send Sync Interest with publish-only `SvsData` (`SvsDataRef` only).

**Receiver procedure:**

1. Identify the sender from the Sync Data signature, or — when the Sync
   Data is PARTIAL — from the first entry, which is the sender's own
   entry per §4.2.
2. If the Sync Data is direct FULL and complete: merge directly.
3. If the Sync Data is publish-only: read `SvsDataRef`; express Interest for
   that name; validate; merge; update local `mhash`.
4. Continue application data fetch via SvsALO (`OnUpdate`) as today.

> **Implementation note:** A consumer may receive many publish-only Sync
> messages that all cross the `mhash` boundary simultaneously. To bound the
> resulting pull fan-in, implementations commonly debounce per-sender pull
> attempts (e.g., 5 seconds per sender prefix). This is a local
> implementation detail and does not affect protocol correctness — a
> debounced pull is equivalent to a slightly delayed pull.

Fetched Data is segmented per the standard NDN convention when it does
not fit in a single packet.

### 5.7 New node join

1. Joining node **N** multicasts Sync Interest whose direct State Vector
   contains only itself: `(Name=N, SeqNo=0)`. The Sync Data's `mhash` is
   the SHA-256 of N's membership set, which is the single member `{N}`.
2. Existing members receive the announcement.
3. Suppression limits duplicate responses; typically one member **A**
   provides recovery state.
4. If FULL fits in a direct packet: **A** responds with `FullStateVector`.
5. If FULL exceeds `SyncVectorThreshold`: **A** uses publish + pull
   (produce at `32=sv/<version>`, then publish-only Sync Data).
6. Normal synchronization proceeds through SvsALO.

### 5.8 Periodic sync in large groups

| Local FULL size | Periodic Sync behavior |
|-----------------|------------------------|
| `≤ SyncVectorThreshold` | Direct FULL (`FullStateVector`) |
| `> SyncVectorThreshold` | Publish + pull (produce full-vector Data, then publish-only Sync Data) |

Periodic sync does not send direct PARTIAL vectors.

### 5.9 Summary of sync triggers

| Event | `size ≤ threshold` | `size > threshold` |
|-------|--------------------|--------------------|
| **New publication** | Direct FULL (`FullStateVector`) | Direct PARTIAL (`PartialStateVector`, or publish + pull fallback) |
| **Periodic sync** | Direct FULL (`FullStateVector`) | Publish + pull |
| **`mhash` mismatch** | Publish + pull (if recovery needed) | Publish + pull |

---

## 6. Comparing and Merging State Vectors

### 6.1 Merge rule

For each matching `(Name, BootstrapTime)`, retain the maximum `SeqNo`.

### 6.2 Outdated vector

State Vector `A` is outdated to `B` if:

- `A` is missing a name present in `B`, or
- `A` has a strictly smaller `SeqNo` for any entry.

This rule applies when `A` is a `FullStateVector`. When `A` is a
`PartialStateVector`, `A`'s omitted names are a subset by design (§4.2):
the sender selected a publication-time subset and `A`'s missing entries
do not carry any information about whether `A` is outdated relative to
`B`.

---

## 7. Examples

### 7.1 Small group

Three nodes `A`, `B`, `C`. Full State Vector fits. `A` publishes; sends
direct FULL Sync Interest `[A:11, B:15, C:25]`. Peers merge.

### 7.2 Large group

Group exceeds `SyncVectorThreshold`. Producer `P` publishes:

- `P` sends direct PARTIAL `SvsData` carrying `PartialStateVector { mhash,
  StateVector=[P:…, A:…, …] }`.
- Receiver merges present entries only.
- If `mhash` differs, `P` (or receiver per policy) triggers publish + pull
  (§5.6).

### 7.3 Large group

- `A` produces full vector at `/group/A/boot/32=sv/<version>`.
- `A` sends publish-only Sync Data `{ SvsDataRef=/group/A/boot/32=sv/<version> }`.
- Peers pull and merge.

### 7.4 New node join

- `N` sends a State Vector containing only itself (`[N:0]`) with `mhash`
  computed over the single-member membership set `{N}`.
- `A` responds with `FullStateVector` or publish + pull.
- `N` merges and synchronizes via SvsALO.

---

## 8. Interoperability

SVS v4 defines a single wire profile. Deployments upgrade all nodes in a
sync group at the same time. Every Sync Data carries exactly one of
`FullStateVector`, `PartialStateVector`, or `SvsDataRef`. The
implementation never emits a bare `StateVector`-only `SvsData`,
regardless of `SyncVectorThreshold`.
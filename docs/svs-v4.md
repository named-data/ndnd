# State Vector Sync (SVS) v4 Specification

SVS v4 is a state-vector synchronization protocol for large sync groups.
It introduces a membership hash (`mhash`), two inline state-vector
encodings (`FULL` and `PARTIAL`), and a third publish-only form that
references a retrievable full vector. Every Sync Data carries `mhash` and
a `VectorType`.

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
| **Inline FULL** | Encoded FULL fits in threshold | `mhash` + `VectorType=FULL` + complete `StateVector` in Sync Data |
| **Inline PARTIAL** | New publication and FULL exceeds threshold | `mhash` + `VectorType=PARTIAL` + subset `StateVector` in Sync Data |
| **Out-of-band FULL** | Periodic sync (large group), or `mhash` mismatch | Produce full vector Data at `32=sv/<version>`; Sync Data carries `mhash` + reference Name only |

**MemberSetHash (`mhash`)** is the SHA-256 digest of the membership
described in §4.2.

**Full state recovery** uses publish + pull when:

1. `mhash` differs from the local membership hash, or
2. Periodic sync runs while the local FULL encoding exceeds
   `SyncVectorThreshold`, or
3. An inline `VectorType = FULL` State Vector is outdated per §6.2.

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

**Sync Data Content:** encoded `SvsData` (§3) — either inline form (FULL
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

**Content:** signed `SvsData` in inline FULL form: `mhash` +
`VectorType = FULL` + complete `StateVector`.

**Publish + pull procedure** (periodic sync, `mhash` recovery, join when
FULL exceeds threshold):

1. Produce the full-vector Data at
   `/<group>/<node>/<boot>/32=sv/<version>` (ndnd segmentation handles
   large content).
2. Send a Sync Interest whose AppParam Sync Data contains publish-only
   `SvsData`: `mhash` + `SvsDataRef` pointing at the published name (§3.1).
3. Receivers pull the referenced Data, validate, and merge.

A Sync message carries either an inline StateVector or a publish-only
reference — not both.

---

## 3. Packet Specification

### 3.1 `SvsData`

`SvsData` has two forms: inline (FULL or PARTIAL) and publish-only. The
`mhash` field is present in both forms. The inline form carries
`VectorType`; the publish-only form does not.

#### 3.1.1 Inline form (FULL or PARTIAL)

Used when the State Vector (full or a publication-time PARTIAL subset) is
carried inline in Sync Data, or in published full-vector Data at
`32=sv/<version>`.

```
SvsData = SVS-DATA-TYPE TLV-LENGTH
          MemberSetHash
          VectorType
          StateVector
```

| Field | TLV type | Value |
|-------|----------|-------|
| `MemberSetHash` | `0xCB` | 32-byte SHA-256 digest (`mhash`) |
| `VectorType` | `0xCD` | `0` = FULL, `1` = PARTIAL |
| `StateVector` | `0xC9` | See §3.2 |

#### 3.1.2 Publish-only form

Used when Sync Data advertises a retrievable full-vector Data name (periodic
sync, `mhash` recovery). `VectorType` and `StateVector` are absent.

```
SvsData = SVS-DATA-TYPE TLV-LENGTH
          MemberSetHash
          SvsDataRef
```

| Field | TLV type | Value |
|-------|----------|-------|
| `MemberSetHash` | `0xCB` | 32-byte SHA-256 digest (`mhash`) |
| `SvsDataRef` | `0x07` (Name) | Name of the published full-vector Data. The receiver strips the trailing version component and uses the resulting `32=sv` prefix as the trust anchor for that sender's retrievable full vectors. |

The inline layout puts `MemberSetHash` and `VectorType` before
`StateVector` (`mhash` at `0xCB`, vector at `0xC9`/`0xCA`).

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

### 3.4 `VectorType` (inline form)

| Value | Name | Meaning |
|-------|------|---------|
| `0` | **FULL** | `StateVector` contains the complete advertised state (§4.1 ordering). |
| `1` | **PARTIAL** | `StateVector` contains a subset (§4.2). Used for new publication only when FULL exceeds threshold. |

`VectorType` is required on the wire because it lets a receiver skip the
more expensive subset-evaluation code path when it sees `FULL`, and lets a
sender guarantee the receiver knows whether missing names imply partition
(FULL) or merely "not included in this subset" (PARTIAL). `mhash` alone
cannot convey this — two parties with identical membership but different
subscription views may legitimately disagree on what subset was sent.

`mhash` is present in both inline and publish-only `SvsData` messages.

---

## 4. State Vector Encoding

### 4.1 FULL State Vector

- Include all known members and their latest sequence numbers per bootstrap.
- Entries ordered in NDN canonical order of `Name`.
- `VectorType = FULL` (§3.4).

### 4.2 PARTIAL State Vector

Used on new publication when
`encoded_size(inline FULL SvsData) > SyncVectorThreshold`.

- `VectorType = PARTIAL` (§3.4).
- **Entry `[0]`** is the sender's own `StateVectorEntry`.
- **Entries `[1…n]`** are in NDN canonical order among included peers.

If the sender-only baseline already exceeds `SyncVectorThreshold`, the
sender falls back to publish + pull rather than emit a PARTIAL vector that
omits the required entry `[0]`.

An implementation MAY use the following selection priority:

| Priority | Include |
|----------|---------|
| 1 | Sender (always) |
| 2 | Repair targets |
| 3 | Propagation targets |
| 4 | Random inactive producers |
| 5 | Others by recency |

Stop adding entries when the estimated inline `SvsData` size approaches
`SyncVectorThreshold`.

### 4.3 `SyncVectorThreshold`

`SyncVectorThreshold` is a fixed library constant (1200 bytes) that bounds
the size of an inline SvsData:

- When `encoded_size(FULL) ≤ SyncVectorThreshold`, nodes use inline FULL
  (with `mhash` and `VectorType=FULL`).
- When `encoded_size(FULL) > SyncVectorThreshold`, nodes switch to PARTIAL
  (publication) or publish + pull (periodic sync and recovery).

The wire format is independent of `SyncVectorThreshold`. All Sync messages
carry `mhash` and a `VectorType` (or `SvsDataRef` for publish-only).

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
| `encoded_size(inline FULL) ≤ SyncVectorThreshold` | Send inline FULL (`mhash` + `VectorType=FULL` + `StateVector`) |
| `encoded_size(inline FULL) > SyncVectorThreshold` | Send inline PARTIAL (`mhash` + `VectorType=PARTIAL` + subset `StateVector`), or publish + pull if the sender-only baseline itself exceeds the threshold |

### 5.3 Sync Ack policy

Sync Interests are unacknowledged.

### 5.4 Steady state and suppression (inline FULL)

For incoming Sync Data with inline `VectorType = FULL`, apply the
steady-state and suppression rules in §5.1–§5.4.

### 5.5 PARTIAL State Vector processing

When `VectorType = PARTIAL`:

1. Parse `mhash` and `StateVector`.
2. Names omitted from the partial `StateVector` are interpreted as "not
   included in this subset" — they do not imply producer removal, outdated
   sender, or sequence rollback.
3. For each present entry, merge newer sequence numbers into local state
   (§6.1).
4. If `mhash` differs from local `mhash`, perform publish + pull recovery
   (§5.6).

PARTIAL processing is the only receive-side change relative to the
inline-FULL path.

### 5.6 Full state recovery (publish + pull)

**Triggers:**

| # | Trigger | Action |
|---|---------|--------|
| 1 | `mhash` in received `SvsData` ≠ locally computed `mhash` | Publish + pull |
| 2 | Inline `VectorType = FULL` is outdated per §6.2 | Merge inline if complete; otherwise publish + pull |
| 3 | Periodic sync while local FULL exceeds `SyncVectorThreshold` | Publish + pull (§5.8) |

Recovery always fetches the complete State Vector from the referenced
`32=sv/<version>` Data.

**Sender procedure** (on `mhash` mismatch or periodic large-group sync):

1. Produce full-vector Data at `/<group>/<sender>/<boot>/32=sv/<version>`
   with inline FULL `SvsData`.
2. Send Sync Interest with publish-only `SvsData` (`mhash` + `SvsDataRef`).

**Receiver procedure:**

1. Identify the sender from the Sync Data signature, or — when the Sync
   Data is PARTIAL — from PARTIAL entry `[0]`, which is the sender's own
   entry per §4.2.
2. If the Sync Data is inline FULL and complete: merge directly.
3. If the Sync Data is publish-only: read `SvsDataRef`; express Interest for
   that name; validate; merge; update local `mhash`.
4. Continue application data fetch via SvsALO (`OnUpdate`) as today.

> **Implementation note:** A consumer may receive many publish-only Sync
> messages that all cross the `mhash` boundary simultaneously. To bound the
> resulting pull fan-in, implementations commonly debounce per-sender pull
> attempts (e.g., 5 seconds per sender prefix). This is a local
> implementation detail and does not affect protocol correctness — a
> debounced pull is equivalent to a slightly delayed pull.

Use ndnd segmentation when fetched Data content is large.

### 5.7 New node join

1. Joining node **N** multicasts Sync Interest whose inline State Vector
   contains only itself: `(Name=N, SeqNo=0)`. The Sync Data's `mhash` is
   the SHA-256 of N's single-member membership list.
2. Existing members receive the announcement.
3. Suppression limits duplicate responses; typically one member **A**
   provides recovery state.
4. If FULL fits inline: **A** responds with inline `VectorType = FULL`.
5. If FULL exceeds `SyncVectorThreshold`: **A** uses publish + pull
   (produce at `32=sv/<version>`, then publish-only Sync Data).
6. Normal synchronization proceeds through SvsALO.

### 5.8 Periodic sync in large groups

| Local FULL size | Periodic Sync behavior |
|-----------------|------------------------|
| `≤ SyncVectorThreshold` | Inline FULL |
| `> SyncVectorThreshold` | Publish + pull (produce full-vector Data, then publish-only Sync Data) |

Periodic sync does not send inline PARTIAL vectors.

### 5.9 Summary of sync triggers

| Event | `size ≤ threshold` | `size > threshold` |
|-------|--------------------|--------------------|
| **New publication** | Inline FULL | Inline PARTIAL (or publish + pull fallback) |
| **Periodic sync** | Inline FULL | Publish + pull |
| **`mhash` mismatch** | Publish + pull (if recovery needed) | Publish + pull |

---

## 6. Comparing and Merging State Vectors

### 6.1 Merge rule

For each matching `(Name, BootstrapTime)`, retain the maximum `SeqNo`.

### 6.2 Outdated vector

State Vector `A` is outdated to `B` if:

- `A` is missing a name present in `B`, or
- `A` has a strictly smaller `SeqNo` for any entry.

This rule applies to `VectorType = FULL`. For `VectorType = PARTIAL`,
omitted names are a subset by design (§4.2): the sender selected a
publication-time subset and `A`'s missing entries do not carry any
information about whether `A` is outdated relative to `B`.

---

## 7. Examples

### 7.1 Small group

Three nodes `A`, `B`, `C`. Full State Vector fits. `A` publishes; sends
inline FULL Sync Interest `[A:11, B:15, C:25]`. Peers merge.

### 7.2 Large group

Group exceeds `SyncVectorThreshold`. Producer `P` publishes:

- `P` sends inline PARTIAL `SvsData { mhash, VectorType=PARTIAL,
  StateVector=[P:…, A:…, …] }`.
- Receiver merges present entries only.
- If `mhash` differs, `P` (or receiver per policy) triggers publish + pull
  (§5.6).

### 7.3 Large group

- `A` produces full vector at `/group/A/boot/32=sv/<version>`.
- `A` sends publish-only Sync Data `{ mhash,
  SvsDataRef=/group/A/boot/32=sv/<version> }`.
- Peers pull and merge.

### 7.4 New node join

- `N` sends self-only vector `[N:0]` with `mhash`.
- `A` responds with inline FULL or publish + pull.
- `N` merges and synchronizes via SvsALO.

---

## 8. Interoperability

SVS v4 defines a single wire profile. Deployments upgrade all nodes in a
sync group at the same time. Every Sync Data carries `mhash` and a
`VectorType` (or `SvsDataRef` for publish-only). The implementation never
emits a `StateVector`-only `SvsData`, regardless of `SyncVectorThreshold`.
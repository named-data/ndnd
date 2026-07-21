# State Vector Sync (SVS) v4 Specification

SVS v4 is a revision of SVS v3 for large synchronization groups. It introduces
a membership hash (`mhash`), two embedded state-vector encodings (`FULL` and
`PARTIAL`), and a third publish-only form that references a retrievable full
vector. The protocol is self-contained: there is no compatibility mode with
plain SVS v3 peers — every Sync Data carries `mhash` and a `VectorType`.

---

## 1. Basic Protocol Design

### 1.1 Small groups

For most deployments, the complete State Vector fits in one Sync packet.
Nodes exchange **full** State Vectors using steady-state, suppression, merge,
and `OnUpdate` semantics inherited from SVS v3.

### 1.2 Large groups

When the encoded State Vector exceeds **`SyncVectorThreshold`** (an
application-configured size budget in bytes), nodes use three dissemination
modes:

| Mode | Trigger | Wire shape |
|------|---------|------------|
| **Embedded FULL** | Encoded FULL fits in threshold | `mhash` + `VectorType=FULL` + complete `StateVector` in Sync Data |
| **Embedded PARTIAL** | New publication and FULL exceeds threshold | `mhash` + `VectorType=PARTIAL` + subset `StateVector` in Sync Data |
| **Publish + pull** | Periodic sync (large group), or `mhash` mismatch | Produce full vector Data at `32=sv/<version>`; Sync Data carries `mhash` + reference Name only |

**MemberSetHash (`mhash`)** is always carried inside `SvsData`. It is a
**membership hash**, not a hash of the full State Vector.

**Full state recovery** uses publish + pull when:

1. `mhash` differs from the local membership hash, or
2. Periodic sync runs while the local FULL encoding exceeds
   `SyncVectorThreshold`, or
3. An embedded `VectorType = FULL` State Vector is outdated per §6.2.

Link-level fragmentation (NDNLPv2) is below this layer. Publishers use the
ndnd object segmentation APIs when retrievable full-vector Data is large.

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

**Sync Data Content:** encoded `SvsData` (§3) — either embedded form (FULL
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

**Content:** signed `SvsData` in embedded FULL form: `mhash` +
`VectorType = FULL` + complete `StateVector`.

**Publish + pull procedure** (periodic sync, `mhash` recovery, join when
FULL exceeds threshold):

1. Produce the full-vector Data at
   `/<group>/<node>/<boot>/32=sv/<version>` (ndnd segmentation handles
   large content).
2. Send a Sync Interest whose AppParam Sync Data contains publish-only
   `SvsData`: `mhash` + `SvsDataRef` pointing at the published name (§3.1).
3. Receivers pull the referenced Data, validate, and merge.

A Sync message carries either an embedded StateVector or a publish-only
reference — not both.

---

## 3. Packet Specification

### 3.1 `SvsData`

`SvsData` has two forms: embedded (FULL or PARTIAL) and publish-only. The
`mhash` field is present in both forms. `VectorType` is only meaningful in
the embedded form.

#### 3.1.1 Embedded form (FULL or PARTIAL)

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

The inline layout extends ndnd v3 `SvsData` with `MemberSetHash` and
`VectorType` before `StateVector`, matching the Python strawman (`mhash` at
`0xCB`, vector at `0xC9`/`0xCA`).

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
- If an entry is absent, its sequence number is treated as 0 for comparison.
- If any received `BootstrapTime` is more than 86400s in the future, the
  entire `StateVector` SHOULD be ignored.

### 3.3 `MemberSetHash` (`mhash`)

`mhash` is a **membership hash**. It is not a hash of the full State Vector
and not a hash of sequence numbers.

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

The Python strawman hashes sorted producer names only. SVS v4 includes
Bootstrap Time in each membership tuple, consistent with SVS v3 identity.

Membership data and State Vector data are separate concepts. Membership is
carried implicitly in the full State Vector. `mhash` summarizes membership
for quick comparison.

### 3.4 `VectorType` (embedded form)

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

`mhash` is present in both embedded and publish-only `SvsData` messages.

---

## 4. State Vector Encoding

### 4.1 FULL State Vector

- Include all known members and their latest sequence numbers per bootstrap.
- Entries ordered in NDN canonical order of `Name`.
- Set `VectorType = FULL`.

### 4.2 PARTIAL State Vector

Used on new publication when
`encoded_size(embedded FULL SvsData) > SyncVectorThreshold`.

- Set `VectorType = PARTIAL`.
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

Stop adding entries when the estimated embedded `SvsData` size approaches
`SyncVectorThreshold`.

### 4.3 `SyncVectorThreshold`

- Configurable implementation parameter (application packet size budget) in
  bytes.
- When `encoded_size(FULL) ≤ SyncVectorThreshold`, nodes use embedded FULL
  (with `mhash` and `VectorType=FULL`).
- When `encoded_size(FULL) > SyncVectorThreshold`, nodes switch to PARTIAL
  (publication) or publish + pull (periodic sync and recovery).

The wire format is independent of `SyncVectorThreshold`. All Sync messages
carry `mhash` and a `VectorType` (or `SvsDataRef` for publish-only).
`SyncVectorThreshold <= 0` selects the default 1200-byte budget.

> **Future work:** the spec currently treats `SyncVectorThreshold` as a
> static application-level constant. Auto-sizing it from observed MTU is a
> planned extension and is intentionally out of scope for v4.

---

## 5. State Sync

Sections 5.1–5.4 inherit their behavior from SVS v3 [Section 4](https://named-data.github.io/StateVectorSync/Specification.html).
SVS v4 adds Sections 5.5–5.9.

### 5.1 Sync Interest timer

- `PeriodicTimeout` default 30s (±10% jitter).
- `SuppressionPeriod` default 200ms.
- `SuppressionTimeout` exponential decay.

### 5.2 Send Sync Interest on new publication

When the node generates a new publication, it immediately emits a Sync
Interest and resets the timer to `PeriodicTimeout`.

| Trigger | Action |
|---------|--------|
| `encoded_size(embedded FULL) ≤ SyncVectorThreshold` | Send embedded FULL (`mhash` + `VectorType=FULL` + `StateVector`) |
| `encoded_size(embedded FULL) > SyncVectorThreshold` | Send embedded PARTIAL (`mhash` + `VectorType=PARTIAL` + subset `StateVector`), or publish + pull if the sender-only baseline itself exceeds the threshold |

### 5.3 Sync Ack policy

Sync Interests are unacknowledged.

### 5.4 Steady state and suppression (embedded FULL)

For incoming Sync Data with embedded `VectorType = FULL`, apply SVS v3
steady-state and suppression rules.

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

This is the receive-side change versus SVS v3.

### 5.6 Full state recovery (publish + pull)

**Triggers:**

| # | Trigger | Action |
|---|---------|--------|
| 1 | `mhash` in received `SvsData` ≠ locally computed `mhash` | Publish + pull |
| 2 | Embedded `VectorType = FULL` is outdated per §6.2 | Merge embedded if complete; otherwise publish + pull |
| 3 | Periodic sync while local FULL exceeds `SyncVectorThreshold` | Publish + pull (§5.8) |

Recovery always fetches the complete State Vector from the referenced
`32=sv/<version>` Data.

**Sender procedure** (on `mhash` mismatch or periodic large-group sync):

1. Produce full-vector Data at `/<group>/<sender>/<boot>/32=sv/<version>`
   with embedded FULL `SvsData`.
2. Send Sync Interest with publish-only `SvsData` (`mhash` + `SvsDataRef`).

**Receiver procedure:**

1. Identify the sender from the Sync Data signature, or — when the Sync
   Data is PARTIAL — from PARTIAL entry `[0]`, which is the sender's own
   entry per §4.2.
2. If the Sync Data is embedded FULL and complete: merge directly.
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

1. Joining node **N** multicasts Sync Interest whose embedded State Vector
   contains only itself: `(Name=N, SeqNo=0)`. The Sync Data's `mhash` is
   the SHA-256 of N's single-member membership list.
2. Existing members receive the announcement.
3. Suppression limits duplicate responses; typically one member **A**
   provides recovery state.
4. If FULL fits inline: **A** responds with embedded `VectorType = FULL`.
5. If FULL exceeds `SyncVectorThreshold`: **A** uses publish + pull
   (produce at `32=sv/<version>`, then publish-only Sync Data).
6. Normal synchronization proceeds through SvsALO.

### 5.8 Periodic sync in large groups

| Local FULL size | Periodic Sync behavior |
|-----------------|------------------------|
| `≤ SyncVectorThreshold` | Embedded FULL |
| `> SyncVectorThreshold` | Publish + pull (produce full-vector Data, then publish-only Sync Data) |

Periodic sync does not send embedded PARTIAL vectors.

### 5.9 Summary of sync triggers

| Event | `size ≤ threshold` | `size > threshold` |
|-------|--------------------|--------------------|
| **New publication** | Embedded FULL | Embedded PARTIAL (or publish + pull fallback) |
| **Periodic sync** | Embedded FULL | Publish + pull |
| **`mhash` mismatch** | Publish + pull (if recovery needed) | Publish + pull |

---

## 6. Comparing and Merging State Vectors

### 6.1 Merge rule

For each matching `(Name, BootstrapTime)`, retain the maximum `SeqNo`.

### 6.2 Outdated vector (embedded FULL only)

State Vector `A` is outdated to `B` if:

- `A` is missing a name present in `B`, or
- `A` has a strictly smaller `SeqNo` for any entry.

For `VectorType = PARTIAL`, the missing-name rule does not apply to names
omitted from the partial message.

---

## 7. Examples

### 7.1 Small group

Three nodes `A`, `B`, `C`. Full State Vector fits. `A` publishes; sends
embedded FULL Sync Interest `[A:11, B:15, C:25]`. Peers merge.

### 7.2 Large group

Group exceeds `SyncVectorThreshold`. Producer `P` publishes:

- `P` sends embedded PARTIAL `SvsData { mhash, VectorType=PARTIAL,
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
- `A` responds with embedded FULL or publish + pull.
- `N` merges and synchronizes via SvsALO.

---

## 8. Interoperability

SVS v4 defines a single wire profile. It does not interoperate with plain
SVS v3 peers in the same sync group: deployments upgrade all nodes to a
v4-conformant implementation at the same time. Every Sync Data carries
`mhash` and a `VectorType` (or `SvsDataRef` for publish-only). The
implementation never emits a legacy `StateVector`-only `SvsData`, regardless
of `SyncVectorThreshold` (a `Threshold ≤ 0` selects the 1200-byte default).
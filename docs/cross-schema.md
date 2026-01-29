# Cross-Namespace Verification Schema

This is the specification for the `CrossSchema` field in NDN Data.
The `CrossSchema` field is used to verify that a given key is allowed to sign a Data in a different namespace.

## TLV Specification

```abnf
CrossSchema = CROSS-SCHEMA-TYPE TLV-LENGTH Data

; Content of the Data in the CrossSchema field
CrossSchemaContent = *SimpleSchemaRule
                     *PrefixSchemaRule
                     *ComponentSchemaRule

SimpleSchemaRule = SIMPLE-SCHEMA-RULE-TYPE TLV-LENGTH
                   NamePrefix
                   KeyLocator

PrefixSchemaRule = PREFIX-SCHEMA-RULE-TYPE TLV-LENGTH
                   NamePrefix

ComponentSchemaRule = COMPONENT-SCHEMA-RULE-TYPE TLV-LENGTH
                      NamePrefix
                      KeyLocator
                      NameComponentIndex
                      KeyComponentIndex

; component indices are absolute (relative to the full Data/KeyLocator names)
; indices are zero-based and MUST be non-negative
; NamePrefix and KeyLocator may include "_" to match any single component
NameComponentIndex = NON-NEGATIVE-INTEGER
KeyComponentIndex = NON-NEGATIVE-INTEGER

NamePrefix = Name
; "_" wildcard is allowed in NamePrefix and KeyLocator for all rule types

CROSS-SCHEMA-TYPE = 600
SIMPLE-SCHEMA-RULE-TYPE = 620
PREFIX-SCHEMA-RULE-TYPE = 622
COMPONENT-SCHEMA-RULE-TYPE = 624
```

## Usage of `CrossSchema`

When an application wants to invite a user `U` in a different namespace to produce data under its namespace, it produces a `CrossSchema` Data and makes it available to `U`. The `CrossSchema` Data contains a list of rules that specify which keys are allowed to sign Data under the namespace of the application.

When `U` wants to sign a Data under the namespace of the application, it includes the `CrossSchema` Data in the Data packet. The verifier first verifies the `CrossSchema` itself, then uses the rules to verify the original Data.

### Example

Suppose the initiator `I` of an application instance has the prefix `/ucla.edu/`.
The application instance uses the prefix `/ucla.edu/wksp/`.

`I` is bootstrapped with the certificates:

1. `/ucla.edu/KEY/kid/iss/ver` signed by a chain ending in the trust anchor.
2. `/ucla.edu/wksp/KEY/kid/iss/ver` signed by `/ucla.edu/KEY/kid/iss/ver`.

`I` now wants to invite `/arizona.edu/alice` to produce data under the prefix `/ucla.edu/wksp/arizona.edu/alice/`. `I` creates the following `CrossSchema` Data:

```ini
Name = /ucla.edu/wksp/32=INVITE/arizona.edu/alice/v=1741157654
Content = SimpleSchemaRule {
  NamePrefix = /ucla.edu/wksp/arizona.edu/alice/
  KeyLocator = /arizona.edu/alice/KEY
}
KeyLocator = /ucla.edu/wksp/KEY/kid/iss/ver
```

Alice is now bootstrapped with the certificate `/arizona.edu/alice/KEY/kid/iss/ver` signed by a chain ending in the trust anchor.

Alice generates a new key and certificate to produce data under the invite prefix:

```ini
Name = /ucla.edu/wksp/arizona.edu/alice/KEY/kid/iss/ver
Content = <pubkey>
KeyLocator = /arizona.edu/alice/KEY/kid/iss/ver
CrossSchema = <data-of> /ucla.edu/wksp/32=INVITE/arizona.edu/alice/v=1741157654
```

Now Alice can generate data under the prefix

```ini
Name = /ucla.edu/wksp/arizona.edu/alice/t=1741157214/seq=1/seg=0
Content = <data>
Signature = <signature>
KeyLocator = /ucla.edu/wksp/arizona.edu/alice/KEY/kid/iss/ver
```

On receiving this data, the verifier takes the following steps:

1. Verify the signature of the data.
1. Use trust schmea to check if the KeyLocator certificate is allowed to sign the data.
1. Fetch the certificate (`/ucla.edu/wksp/arizona.edu/alice/KEY/kid/iss/ver`)
1. Verify the signature on the certificate.
1. Use trust schema to check if the certificate is allowed to sign the data (`no`).
1. At this point, the verifier notes that the certificate has a `CrossSchema` field.
1. Fetch the KeyLocator certificate of the `CrossSchema` Data and verify the chain.
1. Apply each rule in the `CrossSchema` Data to the original Data, and use trust schema to check if the certificate is allowed to sign the data (`yes`).
1. Verify the `CrossSchema` Data signature. Apply the trust schema to the original data name and the `CrossSchema` Data name.
1. Verify the rest of the chain.
1. The data is accepted.

## Specified Rules

The following rules are specified in the `CrossSchema` Data:

### SimpleSchemaRule

A SimpleSchemaRule specifies that a key is allowed to sign Data under a specific prefix.

For example, the following rule specifies that the key `/arizona.edu/alice/KEY` is allowed to sign Data under the prefix `/ucla.edu/wksp/arizona.edu/alice/`:

```ini
Content = SimpleSchemaRule {
  NamePrefix = /ucla.edu/wksp/arizona.edu/alice/
  KeyLocator = /arizona.edu/alice/KEY
}
```

When verifying the application Data, the verifier:

1. Checks if `NamePrefix` is a prefix of the Data name. If yes, continue; otherwise, reject.
2. Checks if `KeyLocator` is a prefix of the KeyLocator in the Data. If yes, accept; otherwise, reject.

### PrefixSchemaRule

A PrefixSchemaRule specifies that any key is allowed to sign data when prepended with the given prefix.

For example, consider the following rule:

```ini
Content = PrefixSchemaRule {
  NamePrefix = /ucla.edu/wksp/open/
}
```

1. `/arizona.edu/alice/KEY` is allowed to sign Data under the prefix `/ucla.edu/wksp/open/arizona.edu/alice/`.
1. `/memphis.edu/bob/KEY` is allowed to sign Data under the prefix `/ucla.edu/wksp/open/memphis.edu/bob/`.
1. `/wustl.edu/carol/sub/KEY` is allowed to sign Data under the prefix `/ucla.edu/wksp/open/wustl.edu/carol/sub/`.

During verification, the verifier:

1. Checks if `NamePrefix` is a prefix of the Data name. If yes, continue; otherwise, reject.
1. Checks if the `KeyName` appears after `NamePrefix` in the Data name. If yes, accept; otherwise, reject.

### ComponentSchemaRule

A ComponentSchemaRule captures a component in the full Data name (not just the suffix after the prefix) and requires the same component to appear at a specific position in the KeyLocator name. This supports invitations where the producer identifier is not the entire suffix of the Data name.

For example:

```ini
Content = ComponentSchemaRule {
  NamePrefix = /ucla.edu/wksp/_/collab   ; "_" matches any single component
  KeyLocator = /arizona.edu/_            ; "_" matches producer id in cert name
  NameComponentIndex = 4
  KeyComponentIndex = 1
}
```

1. The rule matches Data names whose first components are `/ucla.edu/wksp/<anything>/collab/...`; `_` is a single-component wildcard.
1. It captures the 5th component in the full name (index 4) as the producer identifier.
1. The captured component must equal the second component (index 1) in the certificate name after `/arizona.edu`, e.g., `/arizona.edu/alice/KEY/...`.
1. If either prefix check fails or the indexed components differ, the rule rejects the signer.

`NameComponentIndex` and `KeyComponentIndex` are zero-based and must be non-negative.

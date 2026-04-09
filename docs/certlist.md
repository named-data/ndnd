# CertList

This is the specification for a `CertList` Data packet.
A `CertList` allows a verifier to validate a self-signed certificate that is not yet a trusted anchor.
The packet is published under the anchor key name with the `32=auth` keyword, and its `Content` carries a list of certificate names that can be fetched and validated through the normal trust schema.

## TLV Specification

```abnf
; Content of the Data in a CertList packet
CertListContent = 1*CertificateName

CertificateName = Name
```

The `Content` of a `CertList` is the raw concatenation of one or more `Name` TLVs.
There is no wrapper TLV inside the `Content`.
Each entry MUST be a full certificate name.
A `CertList` with empty `Content` is invalid.
If any entry in the `Content` is not a `Name` TLV, the `CertList` is invalid.

## Name Specification

A `CertList` is published under the key name of the self-signed anchor certificate.

```abnf
KeyName = Name
; in practice this is /<identity>/KEY/<keyid>

CertListPrefix = KeyName AUTH-COMPONENT
CertListName = CertListPrefix [Version]

AUTH-COMPONENT = 32=auth
```

The `AUTH-COMPONENT` MUST be the keyword component `32=auth`.
A generic component with the string value `"auth"` is not a `CertList` name.
No components are allowed after the optional `Version` component, except an implicit digest component that may appear during packet transport and is ignored for name matching.

## Usage of `CertList`

When `TrustConfig` verifies a self-signed certificate `A` and `A` is not already a trusted anchor, it looks for a `CertList` under the prefix derived from the anchor key name:

```text
/<identity>/KEY/<keyid>/32=auth
```

The `CertList` Data itself MUST be signed by `A`.
Its `Content` lists alternative certificate names for the same key.
Each listed certificate name MUST stay under the same key name prefix as `A`.

The verifier tries the listed certificates in order.
For each listed name, it fetches the certificate and validates it through the normal trust schema.
If one listed certificate validates successfully, the self-signed certificate `A` is promoted to a trusted anchor and verification continues.

## Example

Suppose an application workspace uses the anchor key `/app/KEY/ws`.
The verifier already trusts the owner namespace `/root`.

The workspace has two certificates for the same key:

1. `/app/KEY/ws/self/v=1741157654`, a self-signed workspace anchor certificate.
1. `/app/KEY/ws/owner/v=1741157600`, the same key certified by an owner certificate that already chains to `/root`.

The workspace publishes the following `CertList` Data:

```ini
Name = /app/KEY/ws/32=auth/v=1741157700
Content = [
  /app/KEY/ws/owner/v=1741157600
]
KeyLocator = /app/KEY/ws/self/v=1741157654
```

Now the workspace issues a user certificate:

```ini
Name = /app/user/alice/KEY/user/app/v=1741157800
Content = <pubkey>
KeyLocator = /app/KEY/ws/self/v=1741157654
```

Alice signs an application Data packet:

```ini
Name = /app/user/alice/data/seg=0
Content = <data>
Signature = <signature>
KeyLocator = /app/user/alice/KEY/user/app/v=1741157800
```

On receiving this Data, the verifier takes the following steps:

1. Verify the signature on the application Data.
1. Fetch and validate Alice's certificate.
1. Observe that the certificate chain reaches `/app/KEY/ws/self/v=1741157654`, which is self-signed but not yet trusted.
1. Fetch `/app/KEY/ws/32=auth` with prefix matching enabled.
1. Verify that the returned Data name matches `/app/KEY/ws/32=auth[/<version>]`.
1. Verify the `CertList` signature using `/app/KEY/ws/self/v=1741157654`.
1. Decode the `Content` as a sequence of certificate names.
1. Fetch `/app/KEY/ws/owner/v=1741157600` from the list and validate it through the normal trust schema.
1. Promote `/app/KEY/ws/self/v=1741157654` to a trusted anchor because the listed certificate for the same key validated.
1. Accept Alice's certificate and the original application Data.

## Validation Rules

The following rules are enforced for a `CertList`:

1. The `CertList` name must match `/<identity>/KEY/<keyid>/32=auth` or `/<identity>/KEY/<keyid>/32=auth/<version>`.
1. The `CertList` Data must be signed by the self-signed anchor certificate currently being validated.
1. The `Content` must decode as one or more `Name` TLVs.
1. Each listed name is tried in order until one validates successfully.
1. Each listed name must stay under the same anchor key prefix.
1. Each fetched listed certificate must be a certificate Data packet with key content.
1. If no listed certificate validates, verification fails.

## Versioning

In the current implementation, validated `CertList` packets are cached by prefix and by full name.
When multiple versions are seen for the same prefix, the cache keeps the one with the highest version number.
A `CertList` name without a version component is treated as version `0` for that comparison.

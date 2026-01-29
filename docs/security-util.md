# Security Utilities Reference

This is the detailed reference for the security utilities in NDNd.

## `ndnd sec keygen`

Keygen generates a new key pair and outputs PEM to stdout.

```bash
# Generate a Ed25519 key for /ndn/alice
ndnd sec keygen /ndn/alice ed25519 > alice.key

# Create a 2048-bit RSA key for /ndn/bob
ndnd sec keygen /ndn/bob rsa 2048 > bob.key

# Create a P-256 ECDSA key for /ndn/carol
ndnd sec keygen /ndn/carol ecc secp256r1 > carol.key
```

## `ndnd sec sign-cert`

sign-cert signs a certificate request or key file and outputs the signed certificate to stdout.

```bash
# Generate a key for /ndn/alice and create a self-signed certificate
ndnd sec keygen /ndn/alice ed25519 > alice.key
ndnd sec sign-cert alice.key < alice.key > alice.cert

# Generate a key for /ndn/bob and create a certificate signed by /ndn/alice
# Sets the issuer field to ALICE
ndnd sec keygen /ndn/bob rsa 2048 > bob.key
ndnd sec sign-cert -issuer ALICE alice.key < bob.key > bob1.cert

# Create a certificate with a defined validity period
ndnd sec sign-cert -issuer ALICE -start 20150101000000 -end 20350101000000 alice.key < bob.key > bob2.cert

# Re-sign the public key in a certificate (or CSR) with a provided key
ndnd sec keygen /ndn/carol ed25519 > carol.key
ndnd sec sign-cert -issuer CAROL carol.key < bob1.cert > bob3.cert
```

## `ndnd sec key-list`

List all keys in the keychain.

```bash
# List all keys in the keychain directory /etc/app/keys
mkdir -p /etc/app/keys
ndnd sec key-list dir:///etc/app/keys
```

## `ndnd sec key-import`

Import keys or certificates to the keychain.

```bash
# Import a key to a directory keychain
ndnd sec key-import dir:///etc/app/keys < alice.key

# Import multiple keys and certificates to a keychain
# Note that this requires ALL files to be PEM encoded
cat bob.key bob1.cert | ndnd sec key-import dir:///etc/app/keys
```

## `ndnd sec key-export`

Export a key from the keychain.

```bash
# Export default key for /ndn/bob from a keychain
ndnd sec key-export dir:///etc/app/keys /ndn/bob

# Export a specific key from a keychain
ndnd sec key-export dir:///etc/app/keys /ndn/bob/KEY/%A6%0Ei%1F%A8J%D4%8E
```

## `ndnd sec key-delete`

Delete a key (and its certificates) from the keychain.

```bash
# Delete a specific key from the keychain
ndnd sec key-delete dir:///etc/app/keys /ndn/bob/KEY/%A6%0Ei%1F%A8J%D4%8E
```

## `ndnd sec cert-delete`

Delete a certificate from the keychain.

```bash
# Delete a certificate by name
ndnd sec cert-delete dir:///etc/app/keys /ndn/bob/KEY/%A6%0Ei%1F%A8J%D4%8E/self/v=1
```

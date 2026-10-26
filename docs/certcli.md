# NDNCERT CLI Reference

The NDNCERT CLI tool can be used to interact with an [NDNCERT](https://github.com/named-data/ndncert) CA.
It allows entities to securely provision certificates after authenticating their identity with the CA.

This example illustrates how to get a certificate from the NDN Testbed CA.

## Getting the CA Certificate

To begin, you need to get the root CA certificate out of band.
The most recent certificates for the NDN Testbed can be obtained [here](https://named-data.net/ndn-testbed/).

If the certificate is in base64, you will need to convert it to TLV or PEM format.

```sh
cat testbed.root.base64 | base64 -d | ndnd sec pem-encode > testbed.root.pem
```

## Requesting a certificate

In this example, we will use the email challenge to request a certificate from the NDN Testbed CA.

Note that the specified output filename does not include an extension.
In this case, a new key will be created since no key is specified with `-k`.
The key will then be written to `alice.key` and the issued certificate to `alice.cert`.

```sh
ndnd certcli -o alice testbed.root.pem
```

The CLI will now prompt you for challenge type. Select the `email` challenge.

```text
Please choose a challenge type:
  1. email
  2. pin
Choice: 1
```

You will next be prompted for the email address to use for the challenge.

```text
Enter your email address: alice@named-data.net
```

The CLI will now attempt to request a certificate from the CA.

```text
================ CA Profile ===============
NDN Testbed NDNCERT CA (Demo)
Name: /ndn
Max Validity: 360h0m0s
Challenges: [email]
===========================================

Challenge Status: need-code
Enter the code sent to your email address:
```

You will receive an email with a code to enter.
On successful verification, the certificate will be issued, and the CLI
will write the key and certificate to the specified output files.

## Using an existing key

You can also use the CLI to certify an existing key.

```sh
# Create a new signing key
# We use a key name corresponding to alice@gmail.com
ndnd sec keygen /ndn/com/gmail/alice ecc secp256r1 > alice.key

# Request a certificate using the existing key
# We specify the challenge type as email with the -c option,
# and the key with the -k option.
ndnd certcli -o alice -k alice.key -c email testbed.root.pem

# Enter the email address and code as before
```

## Go CA authorization and challenges

Configure a CA using `std/examples/ndncert/ca.conf.sample`, with a CA
certificate and its matching private key for the configured `ca-prefix`.
Start the local forwarder before launching the CA:

```sh
ndnd sec certca ca.conf ca.cert ca.key
```

For email verification, configure an SMTP server and set the password in the
environment variable named by `smtp-password-env` (the sample uses
`NDNCERT_SMTP_PASSWORD`). The CA prefix must be reachable by requesting clients.

Use `--data-dir DIR` to retain CA objects, including issued certificates,
across restarts. Active request and challenge state remains in memory, so
clients must start a new request after a CA restart.

PROBE suggests
identities, but does not grant permission to request them. The server enforces
the naming policy even when a client skips PROBE:

- Email verification authorizes exactly the identity computed by the configured
  `name-assignment.email` rule. For example, with CA prefix `/example` and rule
  `/`, `alice@example.org` authorizes `/example/org/example/alice`.
- DNS verification authorizes exactly `CA-prefix/<domain>`, where `<domain>` is
  one generic name component containing a canonical lowercase DNS hostname.
  For example, proving `example.org` authorizes `/example/example.org`, not its
  descendants or other names below the CA prefix.

CHALLENGE Interests must be signed by the key in the original certificate
request. Each request also requires an unchanged random IV prefix and increasing
authenticated AEAD counters; stale/replayed ciphertext is rejected without
repeating the challenge state transition. Clients must retain their send counter
throughout a request. Completed requests cannot issue another certificate.

SMTP and DNS verification run outside the packet-processing loop with bounded
concurrency and network I/O deadlines. Overlapping work on the same request, or
work beyond the concurrency limit, receives a busy error rather than being queued
without a bound. Failed DNS checks, including lookup errors, consume one of the
request's advertised attempts; after exhaustion, start a new request.

# Part 4 — Certificate-Authenticated Secure Channel

## What this is

This is the final version of the protocol. It takes the secure channel
from **Part 3 v3** (X25519 + HKDF + AEAD) and adds **certificate
authentication** so the client can verify the server's identity.

This closes the man-in-the-middle vulnerability that existed in Part 3.

## What changed from Part 3 v3

| Concern               | Part 3 v3               | Part 4                          |
|-----------------------|--------------------------|----------------------------------|
| Key exchange          | X25519 (ephemeral)       | X25519 (ephemeral) — same       |
| Key derivation        | HKDF-SHA256              | HKDF-SHA256 — same              |
| Record protection     | AES-256-GCM + seq nums  | AES-256-GCM + seq nums — same   |
| Server authentication | **None**                 | **Certificate chain + signature**|
| MITM protection       | **None**                 | **Yes**                          |

## The handshake flow

```
Client                                   Server
  |                                         |
  |──── ClientHello ────────────────────>   |  (X25519 public key)
  |                                         |
  |   <──── ServerHello ────────────────    |  (X25519 public key)
  |                                         |
  |   <──── ServerAuth ────────────────     |  (certificate chain
  |                                         |   + CertificateVerify signature)
  |                                         |
  |   [verify chain against trusted root]   |
  |   [verify signature with cert pubkey]   |
  |                                         |
  |   ═══ session keys derived (HKDF) ═══  |
  |                                         |
  |──── encrypted request ──────────────>   |
  |   <──── encrypted response ─────────    |
```

## Why the signature matters

The server signs `client_public_key || server_public_key` with its RSA
private key. This proves two things:

1. **Identity** — the server holds the private key matching the certificate.
2. **Freshness** — the signature is bound to *these specific* ephemeral
   public keys, so a replay or substitution attack fails.

Without the signature, a MITM could intercept the ServerHello, replace
the server's X25519 public key with its own, and establish separate
sessions with the client and server. The certificate chain alone does
not prevent this — the signature over the exchanged keys does.

## Files

| File                     | Purpose                                          |
|--------------------------|--------------------------------------------------|
| `setup_certificates.py`  | Generate root/intermediate/server certs to disk   |
| `handshake.py`           | Authenticated X25519 + certificate handshake      |
| `key_schedule.py`        | HKDF session key derivation (from Part 3 v3)     |
| `record_protection.py`   | AES-GCM record layer (from Part 3 v3)            |
| `server_v4.py`           | Server: loads certs, runs authenticated handshake |
| `client_v4.py`           | Client: loads trusted root, verifies server       |

## How to run

```bash
# Step 1: Generate certificates (run once)
python setup_certificates.py

# Step 2: Start the server
python server_v4.py

# Step 3: In another terminal, run the client
python client_v4.py
```

## What is still simplified

- Only server authentication (no client certificates).
- The signature covers the raw public keys, not a full transcript hash.
  Real TLS 1.3 hashes all handshake messages into the signature.
- No cipher suite negotiation.
- No session resumption or 0-RTT.
- Single connection, then exit.

# Version 2 — X25519 Handshake

> ⬆ [Back to repository root](../../README.md) · [Part 3 overview](../README.md)

## What This Version Does

Replaces the classic Diffie-Hellman math from v1 with **X25519**, a
modern elliptic-curve Diffie-Hellman function.  The result is the same —
both sides compute a shared secret — but the mechanism is cleaner, safer,
and closer to what real-world protocols actually use.

## How X25519 Simplifies the Handshake

| | v1 (Classic DH) | v2 (X25519) |
|---|---|---|
| Parameters | Big prime p + generator g | None — fixed curve |
| Public value size | ~256 bytes (2048-bit) | 32 bytes |
| Negotiation | Must agree on p, g | Nothing to negotiate |
| Code complexity | Manual `pow(g, a, p)` | `private_key.exchange(peer_pub)` |
| Safety | Easy to misuse (weak primes, small subgroups) | Designed to resist misuse |

X25519 uses **Curve25519** — a specific elliptic curve with fixed,
standardized parameters.  There is no prime to choose, no generator to
validate.  You generate a keypair, exchange public keys, and call one
function.

## What "Ephemeral" Means

Each side generates a **fresh keypair** for every handshake session:

```python
client_private = X25519PrivateKey.generate()  # new every time
```

The private key is never stored, never reused, and discarded after the
handshake.  This means that even if an attacker later compromises some
long-term secret, they cannot decrypt **past** sessions because the
ephemeral keys are gone.  This property is called **forward secrecy**.

(We don't have long-term keys yet — that comes with certificates in
Part 4.  But the ephemeral pattern is already in place.)

## Handshake Flow

```
Client                              Server
------                              ------
generate ephemeral keypair          generate ephemeral keypair
(32-byte private + public)          (32-byte private + public)

--- ClientHello [client_pub] --->
                                    --- ServerHello [server_pub] --->

shared = X25519(client_priv,        shared = X25519(server_priv,
                server_pub)                         client_pub)

Both sides now have the same 32-byte shared secret.
```

## How to Run

```bash
# Terminal 1
python server_v2.py

# Terminal 2
python client_v2.py
```

Both sides print the shared secret — compare them.

## Why This Is Closer to Real-World Protocols

TLS 1.3 uses X25519 (or X448) for its key exchange.  The handshake
structure in this version — generate ephemeral keypair, exchange public
keys, compute shared secret — is the same pattern used in production.

## What Is Still Broken

| Problem | Status |
|---------|--------|
| No authentication | **Still broken** — MITM can substitute public keys |
| No session keys | Shared secret is not yet derived into actual keys |
| No record-layer encryption | Application data is not protected |
| No certificates | No identity verification |

The shared secret is just raw key material.  In v3 we use HKDF to
derive actual session keys and protect application data with AEAD.

## Files

| File | Purpose |
|------|---------|
| `handshake.py` | X25519 handshake logic (client + server) |
| `client_v2.py` | Runnable client |
| `server_v2.py` | Runnable server |

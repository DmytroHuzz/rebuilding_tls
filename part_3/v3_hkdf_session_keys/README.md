# Version 3 — HKDF Session Keys

## What This Version Does

This is the final and most important version in Part 3.  It takes the
X25519 shared secret from v2, runs it through **HKDF** to derive actual
session keys, and uses those keys in the **AEAD record layer** from Part 2.

For the first time, the full pipeline is visible:

```
handshake → shared secret → HKDF → session keys → AEAD records
```

No pre-shared keys.  No hardcoded secrets.  Fresh keys for every session.

## What Is HKDF?

HKDF (HMAC-based Key Derivation Function, defined in RFC 5869) turns
raw key material into cryptographically strong, independent keys.

It has two steps:

1. **Extract** — compress the input into a fixed-length pseudorandom key
   (PRK) using HMAC.

2. **Expand** — expand the PRK into output key material of any desired
   length, using "info" labels to derive independent keys.

By using different info labels, we derive two independent keys from one
shared secret:

```python
client_write_key = HKDF(shared_secret, info=b"part3 client write key")
server_write_key = HKDF(shared_secret, info=b"part3 server write key")
```

## Why We Need a KDF

Why not just use the raw X25519 output directly as the AEAD key?

1. **Key separation** — We need two directional keys (client→server and
   server→client).  Using the same key in both directions risks nonce
   reuse, which breaks AES-GCM completely.

2. **Uniform key material** — The X25519 output has specific algebraic
   structure.  HKDF produces output indistinguishable from random bytes.

3. **Protocol structure** — Real TLS 1.3 uses HKDF throughout its key
   schedule.  This version mirrors that design.

## How Session Keys Are Used

| Key | Who encrypts with it | Who decrypts with it |
|-----|---------------------|---------------------|
| `client_write_key` | Client | Server |
| `server_write_key` | Server | Client |

The record format on the wire is the same as Part 2 Stage 3:

```
+-------------+--------------+-------------------------------+
| seq (8 B)   | nonce (12 B) | ciphertext_and_tag (N+16 B)   |
+-------------+--------------+-------------------------------+
```

## How to Run

```bash
# Terminal 1
python server_v3.py

# Terminal 2
python client_v3.py
```

You will see the full flow: handshake, key derivation, then encrypted
application data exchange — all with fresh per-session keys.

## What This Version Is Close To

Structurally, v3 is much closer to real TLS 1.3:

| Feature | v3 | TLS 1.3 |
|---------|-----|---------|
| Key exchange | X25519 | X25519 or X448 |
| Key derivation | HKDF-SHA256 | HKDF-SHA256 or HKDF-SHA384 |
| Record protection | AES-256-GCM | AES-128-GCM, AES-256-GCM, or ChaCha20-Poly1305 |
| Directional keys | Yes | Yes |
| Sequence numbers | Yes | Yes (implicit in nonce construction) |

## What Is Still Missing

| Problem | Why it matters |
|---------|---------------|
| **No server authentication** | Client cannot verify who it's talking to |
| **No certificates** | No binding between identity and public key |
| **No trust chain** | No Certificate Authority hierarchy |
| **No protection against MITM** | An active attacker can substitute public keys |
| **No transcript hash** | Real TLS includes all handshake messages in key derivation |
| **No cipher suite negotiation** | We hardcode AES-256-GCM |

See [mitm_explainer.md](mitm_explainer.md) for a detailed explanation of
why unauthenticated key exchange is still vulnerable.

## Files

| File | Purpose |
|------|---------|
| `key_schedule.py` | HKDF-based key derivation |
| `record_protection.py` | AES-GCM record protection (key as parameter) |
| `handshake.py` | X25519 + HKDF handshake logic |
| `client_v3.py` | Runnable client with full pipeline |
| `server_v3.py` | Runnable server with full pipeline |
| `mitm_explainer.md` | Why MITM is still possible without authentication |

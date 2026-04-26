# Part 2 — Adding Integrity to the Channel

> ⬆ [Back to repository root](../README.md)
> · 📘 Article: [Building Your Own TLS — Part 2](https://www.dmytrohuz.com/p/rebuilding-tls-part-2-adding-integrity)

> **Series**: Rebuilding TLS from scratch (educational)
>
> Part 1 gave us **confidentiality** — AES-CTR encryption over a TCP socket.
> But it also showed that encryption alone is **dangerously insufficient**:
> an attacker can flip ciphertext bits and silently corrupt the plaintext.
>
> Part 2 fixes this by adding **integrity**, evolving through three stages
> until we reach a construction close to what real-world TLS uses.

## What You'll Learn

By the end of Part 2 you will understand:

- Why encryption without integrity is broken (recap from Part 1)
- How HMAC-SHA256 authenticates encrypted records (encrypt-then-MAC)
- Why you need separate keys for encryption and authentication
- Why sequence numbers matter (replay, reordering, stream position)
- How AEAD (AES-GCM) combines confidentiality and integrity in one primitive
- Why AEAD is the modern standard used by TLS 1.3

## The Three Stages

### Stage 1 — HMAC over encrypted records (`crypto_hmac.py`)

We keep AES-CTR encryption from Part 1 and add HMAC-SHA256.

**Construction**: encrypt-then-MAC
- Encrypt plaintext with AES-CTR → (nonce, ciphertext)
- Compute HMAC-SHA256 over `nonce || ciphertext`
- Send `nonce || ciphertext || tag`

**What this fixes**: Bit-flipping attacks from Part 1.  Any modification
to the ciphertext invalidates the HMAC tag.

**Record format**:
```
+----------------+---------------------+----------------+
| nonce (16 B)   | ciphertext (N bytes) | tag (32 bytes) |
+----------------+---------------------+----------------+
```

### Stage 2 — Sequence numbers (`crypto_hmac_seq.py`)

We add an 8-byte monotonic counter to each record.

**What this fixes**: Without sequence numbers, an attacker can replay old
records, reorder records, or drop records — and each individual record
still passes HMAC verification.  The sequence number binds each record to
its position in the stream.

**Record format**:
```
+-------------+----------------+---------------------+----------------+
| seq (8 B)   | nonce (16 B)   | ciphertext (N bytes) | tag (32 bytes) |
+-------------+----------------+---------------------+----------------+
```

**HMAC input**: `seq || nonce || ciphertext`

### Stage 3 — AEAD with AES-GCM (`crypto_aead.py`)

We replace the manual AES-CTR + HMAC construction with AES-GCM.

**Why**: AEAD combines encryption and authentication in a single call.
There is no way to forget the MAC step, get the order wrong, or
accidentally use the same key for both.  AES-GCM is the cipher suite
used by TLS 1.3.

**Record format**:
```
+-------------+--------------+-------------------------------+
| seq (8 B)   | nonce (12 B) | ciphertext_and_tag (N+16 B)   |
+-------------+--------------+-------------------------------+
```

The sequence number is passed as "associated data" — authenticated but
not encrypted.

## Files

| File | Stage | Purpose |
|------|-------|---------|
| `framing.py` | — | Length-prefixed record framing over TCP (unchanged from Part 1) |
| `crypto_hmac.py` | 1 | AES-CTR + HMAC-SHA256, encrypt-then-MAC |
| `crypto_hmac_seq.py` | 2 | Same as above, with sequence numbers in the HMAC input |
| `crypto_aead.py` | 3 | AES-GCM (AEAD) with sequence numbers as associated data |
| `client_v2_hmac.py` | 1 | Client using HMAC-based protection |
| `server_v2_hmac.py` | 1 | Server using HMAC-based protection |
| `client_v2_hmac_seq.py` | 2 | Client using HMAC + sequence numbers |
| `server_v2_hmac_seq.py` | 2 | Server using HMAC + sequence numbers |
| `client_v2_aead.py` | 3 | Client using AEAD protection |
| `server_v2_aead.py` | 3 | Server using AEAD protection |
| `tampering_demo_hmac.py` | 1 | Proves that Part 1's bit-flipping attack is now detected |


## Prerequisites

- Python 3.10+
- `pip install cryptography`

Run commands from the `part_2/` directory:

```bash
cd part_2
```

## How to Run

```bash
pip install cryptography
```

### HMAC client/server (Stage 1)

```bash
# Terminal 1
python server_v2_hmac.py

# Terminal 2
python client_v2_hmac.py
```

### HMAC + sequence numbers client/server (Stage 2)

```bash
# Terminal 1
python server_v2_hmac_seq.py

# Terminal 2
python client_v2_hmac_seq.py
```

### AEAD client/server (Stage 3)

```bash
# Terminal 1
python server_v2_aead.py

# Terminal 2
python client_v2_aead.py
```

### Tampering demo

```bash
python tampering_demo_hmac.py
```

This demo encrypts `b"amount=100"`, flips one ciphertext byte (the same
attack from Part 1), and shows that verification now **fails**.  The
attacker's modification is detected.

## Where to Go Next

- [Part 3](../part_3/README.md) — replace pre-shared keys with ephemeral key exchange
- [Part 4](../part_4/implementation/README.md) — add authentication and trust validation

## What Is Still Broken

Part 2 adds integrity, but the protocol is still far from real TLS:

| Problem | Why it matters | Fixed in |
|---------|---------------|----------|
| Pre-shared keys | Both sides must know the key in advance — no way to establish a key securely over the network | [Part 3](../part_3/README.md) (Diffie-Hellman) |
| No handshake | No negotiation of algorithms, no fresh session keys | [Part 3](../part_3/README.md)+ |
| No peer identity | The client cannot verify it's talking to the real server (and vice versa) | [Part 4](../part_4/implementation/README.md) (certificates) |
| No trust model | No certificate authority chain, no way to decide who to trust | [Part 4](../part_4/implementation/README.md)+ |
| No forward secrecy | If the pre-shared key leaks, all past and future sessions are compromised | [Part 3](../part_3/README.md) (ephemeral DH) |

## Protocol Format Summary

```
Part 1 (encryption only):
  nonce || ciphertext

Part 2, Stage 1 (encrypt-then-MAC):
  nonce || ciphertext || tag

Part 2, Stage 2 (+ sequence numbers):
  seq || nonce || ciphertext || tag

Part 2, Stage 3 (AEAD):
  seq || nonce || ciphertext_and_tag
```

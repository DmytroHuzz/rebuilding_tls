# Part 3 — Key Exchange: From Pre-Shared Keys to Diffie-Hellman

> **Series**: Rebuilding TLS from scratch (educational)
>
> Part 2 gave us strong **record-layer protection** — HMAC for integrity,
> sequence numbers for ordering, and AEAD (AES-GCM) for authenticated
> encryption.  But it had a fatal assumption: both sides started with
> hardcoded, pre-shared keys baked into the source code.
>
> Part 3 removes that assumption.  Both sides now dynamically establish
> fresh session keys through a **handshake**, using public-key cryptography.

## What You'll Learn

By the end of Part 3 you will understand:

- How Diffie-Hellman key exchange lets two parties compute a shared secret
  without ever transmitting it
- How classic DH works with explicit modular arithmetic (g^a mod p)
- How X25519 simplifies the workflow with a fixed, standardized curve
- What "ephemeral" means and why it gives us forward secrecy
- How HKDF derives actual session keys from a raw shared secret
- Why key separation matters (client→server vs server→client keys)
- Why unauthenticated key exchange is still vulnerable to MITM
- How the full pipeline works: handshake → shared secret → HKDF → session keys → AEAD records

## The Three Versions

### v1 — Classic Diffie-Hellman Handshake

**Goal**: Make the shared-secret idea visible with explicit, textbook math.

- Uses a 2048-bit prime and generator g=2 (RFC 3526 Group 14)
- Shows `public = g^private mod p` and `shared = peer_public^private mod p`
- Client and server exchange public values, independently compute the same secret
- No record-layer encryption — just proves the math works

**What this fixes**: Replaces the static pre-shared key assumption from Part 2
with an interactive key exchange.

**What remains broken**: No authentication, no session keys, no record protection.

### v2 — X25519 Handshake

**Goal**: Replace classic DH with the modern primitive used by TLS 1.3.

- X25519 uses a fixed standard curve — no prime/generator management
- 32-byte compact public keys instead of ~256-byte classic DH values
- Ephemeral keypairs — fresh for every session (forward secrecy)
- Same result: both sides compute the same 32-byte shared secret

**What this fixes**: Removes the awkward parameter management of classic DH.
Brings the handshake closer to real-world protocol design.

**What remains broken**: Shared secret is not yet turned into usable session keys.

### v3 — HKDF Session Keys

**Goal**: Complete the pipeline — derive actual AEAD session keys from the
handshake and protect application data.

- X25519 handshake (from v2) produces the raw shared secret
- HKDF-SHA256 derives `client_write_key` and `server_write_key`
- AES-GCM record layer (adapted from Part 2) uses the derived keys
- Application data is now protected with fresh, per-session keys

**What this fixes**: The full gap between "we have a shared secret" and
"application data is protected."

**What remains broken**: No authentication — MITM still possible.

## Educational Progression

```
Part 2 (hardcoded keys):
  AEAD_KEY = b"hardcoded..."  →  AEAD record layer

Part 3, v1 (classic DH):
  g^a mod p, g^b mod p  →  shared secret  →  (printed, not used)

Part 3, v2 (X25519):
  X25519 exchange  →  32-byte shared secret  →  (printed, not used)

Part 3, v3 (HKDF):
  X25519 exchange  →  shared secret  →  HKDF  →  session keys  →  AEAD records
```

Each version builds naturally on the previous one.

## Folder Structure

```
part_3/
  README.md                          ← you are here

  common/
    framing.py                       ← length-prefixed records (unchanged from Part 2)
    handshake_messages.py            ← TLV encoding for handshake fields
    utils.py                         ← small formatting helpers

  v1_classic_dh_handshake/
    README.md
    dh_math.py                       ← modular exponentiation, DH prime/generator
    handshake.py                     ← classic DH handshake logic
    client_v1.py                     ← runnable client
    server_v1.py                     ← runnable server

  v2_x25519_handshake/
    README.md
    handshake.py                     ← X25519 handshake logic
    client_v2.py                     ← runnable client
    server_v2.py                     ← runnable server

  v3_hkdf_session_keys/
    README.md
    key_schedule.py                  ← HKDF key derivation
    record_protection.py             ← AEAD record protection (key as parameter)
    handshake.py                     ← X25519 + HKDF handshake
    client_v3.py                     ← runnable client — full pipeline
    server_v3.py                     ← runnable server — full pipeline
    mitm_explainer.md                ← why MITM is still possible
```


## Prerequisites

- Python 3.10+
- `pip install cryptography`

From repository root, either run commands exactly as shown below or `cd`
into each version folder first.

## How to Run

```bash
pip install cryptography
```

### v1 — Classic DH

```bash
cd part_3/v1_classic_dh_handshake/

# Terminal 1
python server_v1.py

# Terminal 2
python client_v1.py
```

Both sides print the shared secret — they match.

### v2 — X25519

```bash
cd part_3/v2_x25519_handshake/

# Terminal 1
python server_v2.py

# Terminal 2
python client_v2.py
```

Same result, much simpler code.

### v3 — HKDF + AEAD

```bash
cd part_3/v3_hkdf_session_keys/

# Terminal 1
python server_v3.py

# Terminal 2
python client_v3.py
```

Full pipeline: handshake, key derivation, encrypted application data.

## Where to Go Next

- Part 4 (planned): certificates + signatures for authentication
- Part 4+ (planned): trust chain validation and stronger transcript binding

## What Is Still Broken

Part 3 solves the key-distribution problem but introduces a new one:

| Problem | Why it matters | Fixed in |
|---------|---------------|----------|
| **No authentication** | Client cannot verify the server's identity | Part 4 (certificates + signatures) |
| **MITM still possible** | An active attacker can substitute public keys during the handshake | Part 4 |
| **No trust chain** | No Certificate Authority hierarchy to validate identities | Part 4 |
| **No transcript hash** | Real TLS includes handshake messages in key derivation | Part 4+ |
| **No cipher suite negotiation** | We hardcode X25519 + AES-256-GCM | Part 4+ |

**Key insight**: Key exchange gives you confidentiality against passive
eavesdroppers.  Authentication gives you protection against active
attackers.  You need both.  Part 3 has the first half.  Part 4 adds the
second.

See [v3_hkdf_session_keys/mitm_explainer.md](v3_hkdf_session_keys/mitm_explainer.md)
for a detailed walkthrough of the MITM attack.

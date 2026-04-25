# Rebuilding TLS from Scratch (Educational Project)

This repository is the companion code for the blog series:
[**Rebuilding TLS from Scratch — My Complete Learning Journey**](https://www.dmytrohuz.com/p/rebuilding-tls-from-scratch-my-complete).

The goal is to rebuild core TLS ideas step-by-step, starting from insecure plaintext sockets and progressively adding the building blocks used by modern TLS:

1. **Confidentiality** (encryption)
2. **Integrity** (tamper detection)
3. **Key exchange** (ephemeral session keys)
4. **Authentication** (planned)

> ⚠️ This project is intentionally educational and incomplete by design. It is **not** production TLS and should not be used to secure real systems.

## Project Structure

```text
.
├── part_1/  # Encryption only (and why that is not enough)
├── part_2/  # Integrity: HMAC, sequence numbers, AEAD
└── part_3/  # Key exchange: DH -> X25519 -> HKDF session keys
```

## Learning Roadmap

### Part 1 — Encryption Without Integrity

- Baseline plaintext client/server over TCP
- AES-256-CTR encrypted records
- Length-prefixed framing
- Demonstrates CTR bit-flipping malleability attack

📘 Read details: [`part_1/README.md`](part_1/README.md)

### Part 2 — Adding Integrity

- Stage 1: Encrypt-then-MAC (AES-CTR + HMAC-SHA256)
- Stage 2: Sequence numbers to bind record order/position
- Stage 3: AEAD via AES-GCM
- Tampering attempts are detected and rejected

📘 Read details: [`part_2/README.md`](part_2/README.md)

### Part 3 — Handshake & Session Keys

- v1: Classic finite-field Diffie-Hellman (math-first)
- v2: X25519 key exchange (modern primitive)
- v3: HKDF key schedule -> directional session keys -> AEAD records
- Includes MITM explanation for unauthenticated handshakes

📘 Read details: [`part_3/README.md`](part_3/README.md)

## Quick Start

### Prerequisites

- Python 3.10+
- `pip`

Install dependency:

```bash
pip install cryptography
```

### Run a Part

Each part has standalone commands in its own README. Typical flow:

```bash
# 1) open one terminal and start a server
python part_1/server_v1.py

# 2) open second terminal and run the client
python part_1/client_v1.py
```

If a command fails with import/path errors, run from the corresponding folder:

```bash
cd part_3/v3_hkdf_session_keys
python server_v3.py
```

## Current Security Status by Part

| Capability | Part 1 | Part 2 | Part 3 |
|---|---:|---:|---:|
| Confidentiality (encryption) | ✅ | ✅ | ✅ |
| Integrity / tamper detection | ❌ | ✅ | ✅ |
| Replay / ordering protection | ❌ | ✅ (seq in stage 2+) | ✅ |
| Dynamic key agreement | ❌ | ❌ | ✅ |
| Forward secrecy | ❌ | ❌ | ✅ (ephemeral key exchange) |
| Peer authentication | ❌ | ❌ | ❌ |
| MITM resistance | ❌ | ❌ | ❌ |

## What Comes Next

Planned next steps for the series (Part 4+):

- Certificate-based authentication
- Signature verification of handshake data
- Trust chain / CA validation model
- Stronger handshake transcript binding
- More TLS-like negotiation semantics

## Why This Repo Exists

This code prioritizes clarity over completeness so that each concept is visible in isolation. If you are learning TLS internals, this is meant to be read, modified, and broken on purpose.

---

If you are following along from the blog, start with **Part 1**, run every demo, and only then move to the next part.

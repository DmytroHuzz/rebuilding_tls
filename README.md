# Rebuilding TLS from Scratch

> Educational companion code for the article series
> **[Rebuilding TLS from Scratch — My Complete Learning Journey](https://www.dmytrohuz.com/p/rebuilding-tls-from-scratch-my-complete)**.

## What this project is

This repository rebuilds a TLS-like secure channel from the ground up, in
plain Python, one feature at a time. The point is **not** to ship a working
TLS library — there are excellent ones already. The point is to make the
mental model behind TLS visible by writing each layer yourself and seeing
exactly which problem it solves.

Each part starts from the previous one, identifies a concrete weakness,
and adds the smallest piece of cryptography that fixes it. By the end you
have a simplified TLS-like protocol with X.509 certificate authentication,
ephemeral X25519 key exchange, HKDF-derived directional session keys, and
AES-GCM record protection — the same primitives used by TLS 1.3.

If you have used HTTPS as a consumer (web services, API clients, the
browser padlock) but never opened the cover, this project is for you.

> ⚠️ **This is an educational project. It is not production TLS.**
> The code prioritizes clarity over completeness. Do not use it to secure
> real systems. Real applications should use a vetted TLS library
> (`ssl` / `cryptography` / OS-provided TLS).

---

## Start here

Three reasonable ways to read this repo:

### 1. You want the story and the explanations first

Start with the article series:
**[Rebuilding TLS from Scratch — My Complete Learning Journey](https://www.dmytrohuz.com/p/rebuilding-tls-from-scratch-my-complete)**.

For Part 4 specifically, the rendered walkthrough (with diagrams) lives at
**[part_4 walkthrough (HTML)](https://dmytrohuzz.github.io/rebuilding_tls/part_4/walkthrough/walkthrough.html)**.

### 2. You want to run the latest version (Part 4) right now

```bash
pip install -r requirements.txt

# Generate the certificate chain (run once; writes part_4/implementation/certs/).
python part_4/implementation/setup_certificates.py

# Terminal 1: start the authenticated server.
python part_4/implementation/server_v4.py

# Terminal 2: connect with the authenticating client.
python part_4/implementation/client_v4.py
```

You should see the client print `Identity certificate chain: VALID`,
`CertificateVerify: VALID — peer is the real 'localhost'`, and a decrypted
HTTP response. See [the expected output below](#expected-output-of-part-4).

If you have `make`:

```bash
make part4-certs    # one-time
make part4-server   # terminal 1
make part4-client   # terminal 2
```

### 3. You want the full step-by-step learning path

Follow the parts in order. Each part has its own README with run
instructions and a section explaining what is still broken — which
motivates the next part.

1. **[Part 1](part_1/README.md)** — confidentiality only (and why that is not enough).
2. **[Part 2](part_2/README.md)** — integrity (HMAC, sequence numbers, AEAD).
3. **[Part 3](part_3/README.md)** — handshake & session keys (DH → X25519 → HKDF).
4. **[Part 4](part_4/implementation/README.md)** — certificate authentication, closing the MITM gap.

---

## Learning roadmap

### Part 1 — Encryption Without Integrity → [`part_1/README.md`](part_1/README.md)

- **Adds:** AES-256-CTR encryption + length-prefixed framing on top of a
  plain TCP socket.
- **Reveals:** encryption alone is not enough. A live demo
  (`ctr_malleability_demo.py`) flips a single ciphertext byte and turns
  `amount=100` into `amount=900` — without the key.
- **Article:** [Building Your Own TLS — Part 1](https://www.dmytrohuz.com/p/45f5ee51-a230-4937-b025-cf4784aed417).

### Part 2 — Adding Integrity → [`part_2/README.md`](part_2/README.md)

- **Adds:** three stages of integrity protection.
  Stage 1 — encrypt-then-MAC with HMAC-SHA256.
  Stage 2 — sequence numbers bound into the MAC input.
  Stage 3 — AEAD with AES-256-GCM (the construction TLS 1.3 uses).
- **Reveals:** even with integrity, both sides still depend on a hardcoded
  pre-shared key — there is no way to bootstrap a session key over the
  network.
- **Article:** [Building Your Own TLS — Part 2](https://www.dmytrohuz.com/p/rebuilding-tls-part-2-adding-integrity).

### Part 3 — Handshake & Session Keys → [`part_3/README.md`](part_3/README.md)

- **Adds:** an interactive handshake. Three sub-versions:
  v1 — classic finite-field Diffie-Hellman with explicit `g^a mod p`;
  v2 — X25519 (modern elliptic-curve DH);
  v3 — X25519 + HKDF-SHA256 to derive `client_write_key` /
  `server_write_key` for the AES-GCM record layer.
- **Reveals:** the handshake produces matching keys but the peer is
  **not authenticated** — an active attacker can substitute public keys
  in flight (man-in-the-middle). See
  [`part_3/v3_hkdf_session_keys/mitm_explainer.md`](part_3/v3_hkdf_session_keys/mitm_explainer.md).

### Part 4 — Certificate-Authenticated Secure Channel → [`part_4/implementation/README.md`](part_4/implementation/README.md)

- **Adds:** an X.509 certificate chain (root CA → intermediate CA →
  server cert), strict separation of long-term **identity** keys (RSA-2048)
  from per-session **ephemeral** X25519 keys, and a new `ServerAuth`
  handshake message carrying the chain plus an RSA-PSS
  `CertificateVerify` signature over the two ephemeral public keys.
- **Reveals:** the MITM from Part 3 is closed — the client now trusts
  the server's identity (chain) **and** that this specific session was
  signed by it (CertificateVerify).
- **Walkthrough:** rendered HTML at
  [dmytrohuzz.github.io/rebuilding_tls/part_4/walkthrough/walkthrough.html](https://dmytrohuzz.github.io/rebuilding_tls/part_4/walkthrough/walkthrough.html)
  (diagrams, structural explanations, end-to-end code).

---

## Security capability table

| Capability                    | Part 1 | Part 2          | Part 3                | Part 4                          |
|-------------------------------|:------:|:---------------:|:---------------------:|:-------------------------------:|
| Confidentiality (encryption)  |   ✅   |       ✅        |          ✅           |               ✅                |
| Integrity / tamper detection  |   ❌   |       ✅        |          ✅           |               ✅                |
| Replay / order protection     |   ❌   | ✅ (stage 2+)   |          ✅           |               ✅                |
| Dynamic key agreement         |   ❌   |       ❌        |          ✅           |               ✅                |
| Forward secrecy               |   ❌   |       ❌        | ✅ (ephemeral DH)     |       ✅ (ephemeral DH)         |
| Peer authentication           |   ❌   |       ❌        |          ❌           |   ✅ (X.509 + RSA-PSS sig)      |
| MITM resistance               |   ❌   |       ❌        |          ❌           |               ✅                |

---

## Repository structure

```text
rebuilding_tls/
├── README.md                       ← you are here
├── Makefile                        ← shortcut targets for Part 4
├── requirements.txt                ← single dependency: cryptography
│
├── part_1/                         ← encryption only (AES-CTR, no integrity)
│   ├── README.md
│   ├── server_plain.py / client_plain.py     baseline plaintext HTTP
│   ├── server_v1.py   / client_v1.py         AES-CTR encrypted
│   ├── crypto.py, framing.py
│   └── ctr_malleability_demo.py              attack demo: flip 100 → 900
│
├── part_2/                         ← integrity (HMAC → seq nums → AEAD)
│   ├── README.md
│   ├── crypto_hmac.py        / *_v2_hmac.py        stage 1
│   ├── crypto_hmac_seq.py    / *_v2_hmac_seq.py    stage 2
│   ├── crypto_aead.py        / *_v2_aead.py        stage 3 (AES-GCM)
│   └── tampering_demo_hmac.py                      attack now rejected
│
├── part_3/                         ← handshake + session keys
│   ├── README.md
│   ├── common/                     framing, TLV handshake messages, utils
│   ├── v1_classic_dh_handshake/    classic DH (explicit math)
│   ├── v2_x25519_handshake/        X25519
│   └── v3_hkdf_session_keys/       X25519 + HKDF + AEAD record layer
│
└── part_4/                         ← certificate authentication
    ├── implementation/
    │   ├── README.md
    │   ├── certificate.py          build/verify X.509 certificates
    │   ├── setup_certificates.py   one-time: writes certs/*.pem
    │   ├── handshake.py            X25519 + ServerAuth + CertificateVerify
    │   ├── key_schedule.py         HKDF (carried over from Part 3 v3)
    │   ├── record_protection.py    AES-GCM (carried over from Part 3 v3)
    │   ├── server_v4.py            runnable authenticated server
    │   └── client_v4.py            runnable authenticating client
    └── walkthrough/
        ├── walkthrough.qmd         Quarto source of the article
        └── walkthrough.html        self-contained rendered article
```

---

## Prerequisites

- Python **3.10+**
- The single dependency [`cryptography`](https://pypi.org/project/cryptography/):

  ```bash
  pip install -r requirements.txt
  ```

All commands in this README are written to be run from the **repository
root**.

---

## Expected output of Part 4

After `make part4-certs` (or running `setup_certificates.py` directly) and
then running the server and client in two terminals, the **client** prints
something like this:

```
============================================================
Part 4 — Authenticated TLS Client
============================================================
Loaded trusted root: <Name(...,CN=Root CA)>
Connected to 127.0.0.1:10004

[handshake] Client: starting authenticated handshake
  Generated EPHEMERAL X25519 keypair (this session only)
  -> Sent ClientHello (36 bytes)
  <- Received ServerHello
  <- Received ServerAuth
    server identity cert subject: <Name(...,CN=localhost)>
    intermediate certs: 1
  Verifying IDENTITY certificate chain for 'localhost'...
  Identity certificate chain: VALID
  Verifying CertificateVerify (binds identity → this session)...
  CertificateVerify: VALID — peer is the real 'localhost'
  X25519 shared secret: ...
  [key_schedule] Derived session keys: ...
[handshake] Client: handshake complete — authenticated session keys ready

--- Sending request (send_seq=0) ---
  Record sent (97 bytes on wire)

--- Receiving response (expecting recv_seq=0) ---
  [record] unprotect: seq=0, OK (78B)

  Decrypted response:
  HTTP/1.1 200 OK
  Content-Type: text/plain
  Content-Length: 13

  hello, client

Done.
```

---

## This is still not real TLS

Even Part 4 is intentionally simplified. Things real TLS 1.3 has and this
project deliberately leaves out:

- **No mutual TLS** — only the server is authenticated; the client is
  anonymous.
- **No transcript-hash binding** — the `CertificateVerify` signature
  covers only `client_ephemeral_pub ‖ server_ephemeral_pub`, not a hash
  of the entire handshake transcript. Real TLS 1.3 covers everything,
  which prevents a wider class of downgrade attacks.
- **No cipher-suite negotiation** — algorithms (X25519, AES-256-GCM,
  RSA-PSS-SHA-256) are hardcoded.
- **No TLS extensions, no SNI negotiation, no HelloRetryRequest.**
- **No session resumption, no 0-RTT, no PSKs.**
- **No revocation checking** — neither CRL nor OCSP. A compromised
  intermediate stays trusted until expiry.
- **Simplified networking** — single connection per server run, then exit.
  No retry, no graceful shutdown, no fragmentation.
- **Simplified error handling** — invalid records raise; the goal is to
  keep failure paths short and readable rather than production-robust.

---

## Why this repo exists

- **For readers of the series.** Every concept introduced in the articles
  has a corresponding piece of runnable Python here. You can read the
  article, then open the matching file and watch the same idea execute.
- **For engineers who want a TLS mental model.** Each part isolates one
  cryptographic concern (confidentiality / integrity / key agreement /
  authentication) so you can see why TLS looks the way it does — without
  the noise of negotiation, extensions, and historical baggage.
- **As a public learning artifact.** The repo is also a record that I
  learned this material by building it. Anyone reviewing my work
  (recruiters, interviewers, collaborators) can see how I reason about
  systems and security at this level.

---

## Links

- Series landing page — **[Rebuilding TLS from Scratch — My Complete Learning Journey](https://www.dmytrohuz.com/p/rebuilding-tls-from-scratch-my-complete)**
- Part 4 walkthrough (rendered) — [dmytrohuzz.github.io/rebuilding_tls/.../walkthrough.html](https://dmytrohuzz.github.io/rebuilding_tls/part_4/walkthrough/walkthrough.html)
- Repository — [github.com/DmytroHuzz/rebuilding_tls](https://github.com/DmytroHuzz/rebuilding_tls)
- Author's blog / newsletter — [dmytrohuz.com](https://www.dmytrohuz.com/)
- Questions, feedback, found a bug? — [LinkedIn: dmitriyhuz](https://www.linkedin.com/in/dmitriyhuz/)

---

If you are following the article series, start with **Part 1**, run every
demo, and only move forward when you understand exactly which problem the
next part is solving.

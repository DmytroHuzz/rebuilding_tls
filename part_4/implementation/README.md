# Part 4 — Certificate-Authenticated Secure Channel

> ⬆ [Back to repository root](../../README.md)
> · � Article: [Building Your Own TLS — Part 4](https://www.dmytrohuz.com/p/rebuilding-tls-part-4-certificates)
> · �📖 Walkthrough article: [walkthrough.html (rendered)](https://dmytrohuzz.github.io/rebuilding_tls/part_4/walkthrough/walkthrough.html)
> · ✏️ Walkthrough source: [`part_4/walkthrough/walkthrough.qmd`](../walkthrough/walkthrough.qmd)

This is the final and most complete version of the protocol in this
series. It takes the secure channel from **Part 3 v3** (X25519 + HKDF +
AES-GCM) and adds **server authentication** with an X.509 certificate
chain plus a per-session signature.

The result is a simplified TLS-like handshake using exactly the same
cryptographic primitives that real TLS 1.3 uses for an RSA-authenticated
server: ephemeral X25519 key exchange, RSA-PSS over SHA-256 for the
handshake signature, HKDF-SHA256 for key derivation, and AES-256-GCM for
the record layer.

---

## What this part teaches

- **Why Part 3 was still vulnerable.** Key exchange alone gives you a
  shared secret with *somebody*, not necessarily with the server you
  intended to talk to. An active attacker (a man-in-the-middle, or
  *MITM*) can substitute their own X25519 public keys in flight and
  establish two separate sessions — one with the client, one with the
  server — relaying and reading everything.
- **What server authentication actually solves.** A trusted certificate
  chain proves that a particular **public key** belongs to a particular
  **DNS name**. A fresh signature on the handshake proves that the peer
  on this TCP connection is the one that owns the matching private key.
  You need *both*.
- **What the certificate chain proves.** Each certificate in the chain
  is signed by the next one up. Verification walks the chain (leaf →
  intermediate → root) and stops when it reaches a certificate already
  in the client's trust store. Validity windows, name constraints,
  `BasicConstraints(ca=True)`, `KeyUsage`, `ExtendedKeyUsage =
  SERVER_AUTH`, and the SAN DNS-name match are all checked.
- **Why the server must sign handshake data.** A stolen *certificate*
  is not enough to impersonate a server, because the certificate is
  public information. Only the matching *private key* can produce a
  signature that verifies. By signing this session's ephemeral public
  keys, the server proves "I hold the identity private key, **and** I
  am the actual peer of this TCP connection right now".
- **Why identity keys and ephemeral keys are kept strictly separate.**
  This is the single most important mental model in Part 4:

  | Aspect          | 🪪 Identity key (RSA-2048)     | ⚡ Ephemeral key (X25519)             |
  |-----------------|--------------------------------|---------------------------------------|
  | Lifetime        | years                          | one connection                        |
  | Owner           | only the server                | both client and server                |
  | Purpose         | prove **who** the server is    | agree on a **shared secret**          |
  | Stored          | on disk, certified by a CA     | in memory, then discarded             |
  | Used for        | `sign()` / `verify()`          | Diffie–Hellman key agreement          |

  The two key worlds touch in exactly one place: the server uses its
  identity private key to sign the two ephemeral public keys. That
  single signature binds *who* (identity) to *what session*
  (ephemeral keys). Discarding the ephemeral private keys at the end
  of the connection is what gives the protocol forward secrecy.
- **How X25519, HKDF, AES-GCM, X.509, and RSA-PSS fit together.**
  X25519 produces the shared secret. HKDF turns that into two
  directional AES-256-GCM session keys. The X.509 chain authenticates
  the server's identity. RSA-PSS over `client_eph_pub ‖ server_eph_pub`
  binds that identity to this specific session.

---

## What changed compared to Part 3 v3

| Concern               | Part 3 v3                | Part 4                                |
|-----------------------|--------------------------|----------------------------------------|
| Key exchange          | X25519 (ephemeral)       | X25519 (ephemeral) — same             |
| Key derivation        | HKDF-SHA256              | HKDF-SHA256 — same                    |
| Record protection     | AES-256-GCM + seq nums   | AES-256-GCM + seq nums — same         |
| Server identity       | none                     | **X.509 cert chain (root → int → leaf)** |
| Handshake signature   | none                     | **RSA-PSS over the two ephemeral pubkeys** |
| Server authentication | ❌                       | ✅                                     |
| MITM resistance       | ❌                       | ✅                                     |

Everything new lives in the handshake. The record layer
([`record_protection.py`](record_protection.py)) and the key schedule
([`key_schedule.py`](key_schedule.py)) are unchanged from Part 3 v3.

---

## Architecture / handshake flow

```
Client                                       Server
  │                                            │
  │  generates ⚡ client_ephemeral_(priv,pub)  │  generates ⚡ server_ephemeral_(priv,pub)
  │                                            │
  ├── ClientHello { ⚡ client_eph_pub } ──────►│
  │                                            │
  │ ◄────── ServerHello { ⚡ server_eph_pub } ─┤
  │                                            │
  │ ◄────── ServerAuth { 📜 server_identity_cert,  ┤
  │                      📜 intermediate_cert,     │
  │                      ✍️ CertificateVerify } ───┤
  │                                            │
  │  1) Verify identity cert chain to trusted_root │
  │  2) Verify CertificateVerify signature with    │
  │     server_identity_cert.public_key over       │
  │     (client_eph_pub ‖ server_eph_pub)          │
  │                                            │
  │  shared_secret = X25519(client_eph_priv,   │  shared_secret = X25519(server_eph_priv,
  │                         server_eph_pub)    │                          client_eph_pub)
  │                                            │
  │  HKDF → client_write_key, server_write_key │  (same)
  │                                            │
  ├── AES-GCM record (request) ───────────────►│
  │ ◄────────── AES-GCM record (response) ─────┤
```

The full pipeline, end to end:
`X25519 → shared secret → HKDF → directional session keys → AEAD records`,
with the X.509 chain + CertificateVerify gating everything that follows.

---

## Files to read first

Read in this order to follow the logic:

1. [`certificate.py`](certificate.py) — `CertificateName`, the
   extension helpers (`ca_extensions`, `server_extensions`),
   `issue_certificate`, and `verify_server_certificate`. Builds and
   validates X.509 certificates.
2. [`setup_certificates.py`](setup_certificates.py) — generates a
   three-level chain (root → intermediate → server) and writes PEM
   files into `certs/`. Run once before any client/server demo.
3. [`handshake.py`](handshake.py) — the heart of Part 4. Contains the
   strict `identity_*` / `ephemeral_*` naming convention, the
   `_sign_ephemeral_pubkeys_with_identity` /
   `_verify_ephemeral_pubkeys_with_identity` helpers, and the
   `client_handshake` / `server_handshake` functions that wire the
   chain verification together with the X25519 key agreement.
4. [`server_v4.py`](server_v4.py) and
   [`client_v4.py`](client_v4.py) — small, linear top-level scripts
   that load credentials, run the handshake, and exchange one record.
5. [`key_schedule.py`](key_schedule.py) and
   [`record_protection.py`](record_protection.py) — unchanged from
   Part 3 v3; included here to keep the part self-contained.

For a deeper walkthrough with diagrams of every concept (the two key
worlds, the cert structure under the hood, how SKI/AKI link the chain,
what `sign()` and `verify()` actually compute, and the live MITM
scenario), read the **[full walkthrough](https://dmytrohuzz.github.io/rebuilding_tls/part_4/walkthrough/walkthrough.html)**.

---

## How to run

All commands assume you are at the **repository root**.

### Prerequisites

```bash
pip install -r requirements.txt
```

### Run Part 4

```bash
# 1) One-time: generate the certificate chain into part_4/implementation/certs/.
python part_4/implementation/setup_certificates.py

# 2) TERMINAL 1 — start the authenticated server.
python part_4/implementation/server_v4.py

# 3) TERMINAL 2 — connect with the authenticating client.
python part_4/implementation/client_v4.py
```

Or, with `make` (same three commands):

```bash
make part4-certs    # one-time
make part4-server   # terminal 1
make part4-client   # terminal 2
```

The server handles **one** connection and exits. To run again, restart
the server.

---

## What to observe

Things worth noticing while the demo runs:

- The client prints the **EPHEMERAL** X25519 public it generated and the
  **EPHEMERAL** X25519 public it received from the server. Run again
  and these change every time. Run the same script twice in a row and
  the values are different — that is forward secrecy in action.
- The client prints `Verifying IDENTITY certificate chain for
  'localhost'... VALID` *before* it touches the signature. This
  ordering is important: the public key is only trusted **after** the
  chain is validated.
- Then the client prints `Verifying CertificateVerify (binds identity
  → this session)... VALID — peer is the real 'localhost'`. That is
  the per-session binding.
- Both sides arrive at the **same** X25519 shared secret and derive the
  **same** `client_write_key` / `server_write_key`. You can compare the
  hex previews printed on each side.
- The application data (an HTTP-style request and response) flows over
  the AES-GCM record layer with sequence number 0.

### Expected output — client

```
============================================================
Part 4 — Authenticated TLS Client
============================================================
Loaded trusted root: <Name(...,CN=Root CA)>
Connected to 127.0.0.1:10004

[handshake] Client: starting authenticated handshake
  Generated EPHEMERAL X25519 keypair (this session only)
  client_ephemeral_public: 4d2877560954c974a5305ee0bafbf533...
  -> Sent ClientHello (36 bytes)
  <- Received ServerHello
  server_ephemeral_public: bad004d51ee0537de7121c1052c35e3e...
  <- Received ServerAuth
    server identity cert subject: <Name(...,CN=localhost)>
    intermediate certs: 1
  Verifying IDENTITY certificate chain for 'localhost'...
  Identity certificate chain: VALID
  Verifying CertificateVerify (binds identity → this session)...
  CertificateVerify: VALID — peer is the real 'localhost'
  X25519 shared secret: e56cca9bfdac7babbcd846a9264b7d5f...
  [key_schedule] Derived session keys:
    client_write_key = eadc0caf32486ea235f47ec32b02fcde...
    server_write_key = 559970d9dc9cd0ba8f7737b3293e9bf0...
[handshake] Client: handshake complete — authenticated session keys ready

--- Sending request (send_seq=0) ---
  [record] protect: seq=0, nonce=dee6774636672bd2010a0b7d, sealed=77B
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

### Expected output — server

```
============================================================
Part 4 — Authenticated TLS Server
============================================================
Loaded identity certificate: <Name(...,CN=localhost)>
Loaded 1 intermediate certificate(s)
Listening on 127.0.0.1:10004
Connected by ('127.0.0.1', <random>)

[handshake] Server: starting authenticated handshake
  Generated EPHEMERAL X25519 keypair (this session only)
  server_ephemeral_public: bad004d51ee0537de7121c1052c35e3e...
  <- Received ClientHello
  client_ephemeral_public: 4d2877560954c974a5305ee0bafbf533...
  -> Sent ServerHello (36 bytes)
  -> Sent ServerAuth (2217 bytes)
    identity certs: 2, CertificateVerify: 256B
  X25519 shared secret: e56cca9bfdac7babbcd846a9264b7d5f...
  [key_schedule] Derived session keys:
    client_write_key = eadc0caf32486ea235f47ec32b02fcde...
    server_write_key = 559970d9dc9cd0ba8f7737b3293e9bf0...
[handshake] Server: handshake complete — session keys ready
```

---

## What the client verifies, in order

1. **Chain to a trusted root.** `verify_server_certificate(...)` builds
   the chain `server_identity_cert → intermediate → trusted_root`,
   checks every signature, validity window, `BasicConstraints`,
   `KeyUsage`, `ExtendedKeyUsage = SERVER_AUTH`, and that the
   `SubjectAlternativeName` in the leaf includes `localhost`.
2. **CertificateVerify signature.** Using the **identity public key
   from the now-trusted leaf certificate**, the client verifies the
   RSA-PSS-SHA-256 signature over
   `client_ephemeral_public ‖ server_ephemeral_public`. This proves the
   peer holds the identity private key **and** signed *these specific*
   ephemeral keys (no replay).

If either step fails, the client raises and the connection is aborted
before any application data is sent.

---

## What is still simplified vs. real TLS 1.3

Even though Part 4 finally has authentication, several real-TLS features
are deliberately left out:

- **No mutual TLS** — the client does not present a certificate.
- **No transcript-hash binding** — the signature covers only
  `client_eph_pub ‖ server_eph_pub`, not a hash of the entire
  handshake transcript. Real TLS 1.3 covers all handshake messages,
  which prevents a wider class of downgrade attacks.
- **No cipher-suite negotiation** — X25519, AES-256-GCM, and
  RSA-PSS-SHA-256 are hardcoded.
- **No TLS extensions, no SNI negotiation, no HelloRetryRequest.**
- **No revocation checking** (CRL / OCSP). A compromised intermediate
  remains trusted until expiry.
- **No session resumption / 0-RTT / PSK.**
- **Single connection per server run, then exit.** No connection
  pooling, no graceful shutdown, no record fragmentation.
- **PEM files on disk** instead of a real PKI deployment.

These trade-offs keep every line of code readable while preserving the
core security property the previous parts were missing: peer
authentication and MITM resistance.

---

## File reference

| File                                              | Purpose                                                       |
|---------------------------------------------------|---------------------------------------------------------------|
| [`certificate.py`](certificate.py)                | Build, sign, and verify X.509 certs and chains.               |
| [`setup_certificates.py`](setup_certificates.py)  | One-time: generate root → intermediate → server chain to disk. |
| [`handshake.py`](handshake.py)                    | Authenticated X25519 handshake; `identity_*` / `ephemeral_*` separation. |
| [`key_schedule.py`](key_schedule.py)              | HKDF-SHA256 session key derivation (from Part 3 v3).          |
| [`record_protection.py`](record_protection.py)    | AES-GCM record layer (from Part 3 v3).                        |
| [`server_v4.py`](server_v4.py)                    | Runnable server: loads identity material, runs handshake.     |
| [`client_v4.py`](client_v4.py)                    | Runnable client: loads trusted root, verifies and connects.   |

---

## Where to go next

- Read the **[full walkthrough article](https://dmytrohuzz.github.io/rebuilding_tls/part_4/walkthrough/walkthrough.html)**
  if you want diagrams and structural deep-dives (cert layout under the
  hood, SKI/AKI chain matching, what `sign()`/`verify()` actually
  compute, the live MITM scenario this protocol defeats).
- Re-read [Part 3](../../part_3/README.md) and try to construct a
  valid CertificateVerify by hand — it is impossible without the
  identity private key, which is the whole point.
- Possible follow-up parts (not implemented in this repo):
  mutual TLS, full transcript-hash binding, cipher-suite negotiation,
  session resumption, OCSP / CRL revocation.

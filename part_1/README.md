# Part 1 — Encryption Without Integrity

> ⬆ [Back to repository root](../README.md)
> · 📘 Article: [Building Your Own TLS — Part 1](https://www.dmytrohuz.com/p/45f5ee51-a230-4937-b025-cf4784aed417)

## What You'll Learn

This part demonstrates the **first step** toward building a secure channel:
adding encryption to a plain TCP connection. But it also reveals a critical
flaw — encryption alone is **not enough**.

By the end you'll understand:
- How plain TCP exposes everything to anyone watching the network
- How AES-256-CTR encrypts traffic so eavesdroppers see only random bytes
- Why length-prefixed framing is needed on top of TCP
- **Why encryption without integrity is dangerously broken** — an attacker
  can silently modify encrypted data without knowing the key

## Files

| File | Purpose |
|------|---------|
| `server_plain.py` | Baseline: unencrypted HTTP server |
| `client_plain.py` | Baseline: unencrypted HTTP client |
| `crypto.py` | AES-256-CTR encryption/decryption with a pre-shared key |
| `framing.py` | Length-prefixed message framing over TCP |
| `server_v1.py` | Encrypted server (uses `crypto.py` + `framing.py`) |
| `client_v1.py` | Encrypted client (uses `crypto.py` + `framing.py`) |
| `ctr_malleability_demo.py` | **Attack demo**: flips `amount=100` → `amount=900` without the key |


## Prerequisites

- Python 3.10+
- `pip install cryptography`

Run commands from the `part_1/` directory:

```bash
cd part_1
```

## How to Run

```bash
pip install cryptography

# Step 1: See the problem — plaintext HTTP (try capturing with Wireshark)
python server_plain.py     # Terminal 1
python client_plain.py     # Terminal 2
# → Everything is visible in the packet capture

# Step 2: Add encryption
python server_v1.py        # Terminal 1
python client_v1.py        # Terminal 2
# → Wireshark now shows only random-looking bytes

# Step 3: See why encryption alone isn't enough
python ctr_malleability_demo.py
# → "amount=100" becomes "amount=900" — no key needed!
```

## Wire Format

Each encrypted message on the wire looks like this:

```
+------------------+----------------+---------------------+
| length (4 bytes) | nonce (16 B)   | ciphertext (N bytes) |
+------------------+----------------+---------------------+
  big-endian uint32   random, unique   same size as plaintext
  (framing.py)        (crypto.py)      (crypto.py)
```

## The Vulnerability: CTR Bit-Flipping

AES-CTR works by XORing a keystream with the plaintext. This means if you
XOR the **ciphertext** with a known difference, the plaintext changes by
exactly that difference — no key required.

`ctr_malleability_demo.py` demonstrates this:

```
Original plaintext:  amount=100
                            ^ ASCII '1' = 0x31

Attacker XORs ciphertext byte with 0x08 (= 0x31 ⊕ 0x39)

Decrypted result:    amount=900
                            ^ ASCII '9' = 0x39
```

The decryption succeeds with **no error**. Neither the client nor the server
can tell the message was tampered with. This is why encryption without
integrity checking is considered broken.

## Where to Go Next

- [Part 2](../part_2/README.md) — integrity (HMAC, sequence numbers, AEAD)
- [Part 3](../part_3/README.md) — dynamic key exchange (DH → X25519 + HKDF)
- [Part 4](../part_4/implementation/README.md) — authentication via X.509
  certificates and a handshake signature (closes the MITM gap)

## What's Missing (Fixed in Later Parts)

| Problem | Solution | Where |
|---------|----------|-------|
| No integrity — bit-flipping attacks | HMAC or AEAD (AES-GCM) | [Part 2](../part_2/README.md) |
| Hardcoded pre-shared key | Diffie-Hellman key exchange | [Part 3](../part_3/README.md) |
| No authentication — who is the server? | Certificates + signatures | [Part 4](../part_4/implementation/README.md) |

## Wireshark Tips

To inspect the traffic with Wireshark:

1. Capture on the **Loopback** interface
2. Filter: `tcp.port == 8081`
3. With `server_plain.py` — you'll see the full HTTP request/response in cleartext
4. With `server_v1.py` — the payload is encrypted; you'll only see random bytes
5. Look for `[PSH, ACK]` packets with `Len > 0` — those carry actual data

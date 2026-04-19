# Version 1 — Classic Diffie-Hellman Handshake

## What This Version Does

This is the first step toward replacing the hardcoded pre-shared keys from
Part 2.  Instead of both sides starting with the same secret baked into
source code, they **dynamically compute** a shared secret using the classic
Diffie-Hellman (DH) key exchange.

## What Is Diffie-Hellman?

Diffie-Hellman is a key-agreement protocol that lets two parties — who
have never communicated before — arrive at the same shared secret over an
insecure channel, without ever transmitting the secret itself.

### The Math

Both sides agree on two public parameters:

- **p** — a large prime number
- **g** — a generator (base) for the multiplicative group modulo p

Then:

1. Client picks a random private exponent **a** and computes:
   `A = g^a mod p` (this is the client's public value)

2. Server picks a random private exponent **b** and computes:
   `B = g^b mod p` (this is the server's public value)

3. They exchange A and B over the wire (in the clear — that's fine).

4. Client computes: `shared = B^a mod p = g^(ba) mod p`
   Server computes: `shared = A^b mod p = g^(ab) mod p`

Since `g^(ab) mod p = g^(ba) mod p`, both sides get the same value.

An eavesdropper sees `g`, `p`, `A`, and `B`, but computing the shared
secret from those requires solving the **discrete logarithm problem**,
which is computationally infeasible for large primes.

### Parameters in This Demo

We hardcode the parameters from **RFC 3526, Group 14** (a 2048-bit prime,
generator g=2).  In a real protocol, parameters could be negotiated
dynamically or selected from well-known standardized groups.

## Handshake Flow

```
Client                              Server
------                              ------
generate private_a
compute  A = g^a mod p
                                    generate private_b
                                    compute  B = g^b mod p

--- ClientHello [A] --->
                                    --- ServerHello [B] --->

shared = B^a mod p                  shared = A^b mod p
(same value!)                       (same value!)
```

## How to Run

```bash
# Terminal 1
python server_v1.py

# Terminal 2
python client_v1.py
```

Both sides will print the shared secret.  Compare them — they match.

## Why This Version Exists

This version exists **pedagogically** — to make the core idea of
public-key exchange visible with explicit, readable math.  The formulas
`g^a mod p` and `B^a mod p` are right there in the code.

We do **not** want to keep this version for a real protocol because:

- managing a safe prime and generator is awkward
- classic DH with raw integers is slower than curve-based alternatives
- modern protocols use X25519, which handles all the parameter-safety
  concerns internally

## What Is Still Broken

| Problem | Status |
|---------|--------|
| No authentication | **Still broken** — MITM can intercept and substitute public values |
| No session keys | Shared secret is not yet turned into usable keys |
| No record-layer protection | Application data is not encrypted in this version |
| No certificates | No way to verify who you're talking to |

## Files

| File | Purpose |
|------|---------|
| `dh_math.py` | Modular exponentiation helpers, DH prime/generator |
| `handshake.py` | Client/server handshake logic |
| `client_v1.py` | Runnable client |
| `server_v1.py` | Runnable server |

# Man-in-the-Middle: Why Key Exchange Is Not Authentication

## The Problem

Part 3 replaced the pre-shared key from Part 2 with a Diffie-Hellman
handshake.  Both sides now dynamically establish a shared secret.  This
is a huge improvement — we no longer need to distribute secrets in advance.

But there is a critical gap: **key exchange is not authentication**.

The handshake proves that "someone" computed a shared secret with you.
It does NOT prove **who** that someone is.

## The Attack

A man-in-the-middle (MITM) attacker — let's call her Mallory — sits
between the client and the server and intercepts the handshake:

```
Client                   Mallory                   Server
------                   -------                   ------

generate keypair         generate keypair A         generate keypair
                         generate keypair B

--- ClientHello --->
[client_pub]
                         intercepts client_pub
                         --- ClientHello --->
                         [mallory_pub_B]
                                                   receives mallory_pub_B
                                                   (thinks it's the client)

                         <--- ServerHello ---
                         [server_pub]
intercepts server_pub
<--- ServerHello ---
[mallory_pub_A]
                                                   shared_server = X25519(
receives mallory_pub_A                               server_priv,
(thinks it's the server)                             mallory_pub_B)

shared_client = X25519(  shared_A = X25519(
  client_priv,             mallory_priv_A,
  mallory_pub_A)           client_pub)

                         shared_B = X25519(
                           mallory_priv_B,
                           server_pub)
```

Now:
- **Client** has a shared secret with **Mallory** (thinks it's the server)
- **Server** has a shared secret with **Mallory** (thinks it's the client)
- **Mallory** has a shared secret with each side

Mallory can now:
1. Decrypt the client's messages (using shared_A)
2. Read them, modify them if she wants
3. Re-encrypt them for the server (using shared_B)
4. The server accepts them — the AEAD is valid
5. Do the same in the other direction

Neither the client nor the server can detect this.

## Why This Happens

The handshake only establishes that "I computed a shared secret with
whoever sent me this public key."  It does NOT establish "the public key
came from the server I intended to talk to."

The missing piece is **authentication** — proving the identity of the
peer.  In the real world, this is done with:

1. **Certificates** — the server has a certificate signed by a trusted
   Certificate Authority (CA) that binds the server's identity (e.g.,
   its domain name) to a public key.

2. **Digital signatures** — the server signs part of the handshake with
   its private key.  The client verifies the signature using the public
   key from the certificate.

3. **Trust chain** — the client trusts a set of root CAs.  The server's
   certificate is signed by one of those CAs (or by an intermediate CA
   that chains up to a root CA).

Without these, a correct shared secret with the wrong party is still a
protocol failure.

## What Changes in Part 4

Part 4 will introduce:
- Server certificates (X.509 or a simplified equivalent)
- Digital signatures over the handshake
- A trust model that lets the client verify the server's identity
- Protection against MITM by binding the handshake to a verified identity

## Key Takeaway

> **Key exchange gives you confidentiality against passive eavesdroppers.**
>
> **Authentication gives you protection against active attackers (MITM).**
>
> **You need both.**

This is why real TLS combines Diffie-Hellman key exchange with
certificate-based authentication.  Part 3 has the first half.  Part 4
adds the second.

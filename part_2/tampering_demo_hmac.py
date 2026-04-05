# tampering_demo_hmac.py
#
# TAMPERING DEMO — HMAC STOPS THE ATTACK
#
# WHAT THIS FILE DOES:
#   In Part 1, ctr_malleability_demo.py showed that an attacker could flip
#   bits in AES-CTR ciphertext and the decryption would succeed silently
#   with corrupted plaintext.  That was the whole motivation for Part 2.
#
#   This demo proves the fix works.  We:
#     1. Encrypt + HMAC protect a plaintext (b"amount=100")
#     2. Flip one byte in the protected output (simulating an attacker)
#     3. Try to verify_then_decrypt() — it FAILS with a clear error
#
#   The HMAC catches the modification because any change to the ciphertext
#   invalidates the tag.  The attacker cannot recompute the tag without
#   knowing the MAC key.
#
# HOW TO RUN:
#   python tampering_demo_hmac.py
#
# EXPECTED OUTPUT:
#   - Original plaintext shown
#   - Tampering applied
#   - Verification fails with a clear message
#   - Demonstrates that Part 1's vulnerability is now fixed

from crypto_hmac import encrypt_then_mac, verify_then_decrypt, NONCE_LEN

print("=" * 60)
print("Part 2 — Tampering Demo: HMAC detects bit-flipping")
print("=" * 60)

# ---------------------------------------------------------------------------
# Step 1: Protect a plaintext with encrypt-then-MAC.
# ---------------------------------------------------------------------------
original = b"amount=100"
print(f"\nOriginal plaintext: {original}")

print("\n--- Protecting with encrypt-then-MAC ---")
protected = encrypt_then_mac(original)
print(f"  Protected payload: {len(protected)} bytes")

# ---------------------------------------------------------------------------
# Step 2: Tamper with the ciphertext.
# This is the same attack as Part 1's ctr_malleability_demo.py:
# we flip a bit in the ciphertext to change '1' to '9'.
# ---------------------------------------------------------------------------
print("\n--- Simulating attacker: flipping one byte in ciphertext ---")

tampered = bytearray(protected)
# The ciphertext starts after the 16-byte nonce.
# We target the byte that corresponds to the '1' in "amount=100".
target_index = NONCE_LEN + len("amount=")
tampered[target_index] ^= 0x08  # XOR to flip '1' (0x31) → '9' (0x39)

print(f"  Flipped byte at index {target_index} (ciphertext region)")
print(f"  XOR mask: 0x08")

# ---------------------------------------------------------------------------
# Step 3: Try to verify + decrypt the tampered payload.
# ---------------------------------------------------------------------------
print("\n--- Attempting to verify tampered record ---")

try:
    result = verify_then_decrypt(bytes(tampered))
    # If we reach here, something is very wrong.
    print(f"  ERROR: Decryption succeeded — this should not happen!")
    print(f"  Result: {result}")
except ValueError as e:
    # This is the EXPECTED outcome.
    print(f"\n  TAMPERED RECORD REJECTED: {e}")

# ---------------------------------------------------------------------------
# Step 4: Show that an untampered record still works fine.
# ---------------------------------------------------------------------------
print("\n--- Verifying original (untampered) record ---")
result = verify_then_decrypt(protected)
print(f"  Decrypted successfully: {result}")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print("\n" + "=" * 60)
print("SUMMARY:")
print("  In Part 1, this bit-flip silently changed 'amount=100' to")
print("  'amount=900'.  The decryption succeeded with NO error.")
print()
print("  In Part 2, the HMAC catches the modification.  The record")
print("  is rejected BEFORE decryption even happens.  The attacker")
print("  cannot forge a valid tag without the MAC key.")
print("=" * 60)

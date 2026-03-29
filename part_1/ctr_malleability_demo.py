from crypto import encrypt_message, decrypt_message

original = b"amount=100"
encrypted = encrypt_message(original)

nonce = encrypted[:16]
ciphertext = bytearray(encrypted[16:])

# Change '1' -> '9'
# ASCII '1' = 0x31
# ASCII '9' = 0x39
# Difference = 0x08

index_of_digit = len("amount=")
ciphertext[index_of_digit] ^= 0x08

modified = nonce + bytes(ciphertext)
decrypted = decrypt_message(modified)

print("Original :", original)
print("Modified :", decrypted)

# Simple encryption/decryption tool

This is a simple CLI program and library to encrypt and decrypt files.

The AEAD used is ChaCha20-Poly1305 and the KDF used is argon2. Only argon2id is supported.

# Limitations

- This program does not commit to securely wipe sensitive data from memory, such as passwords and cryptography keys.

# Simple encryption/decryption tool

This is a simple CLI program to encrypt and decrypt files.

The AEAD used is ChaCha20-Poly1305 and the KDF used is argon2. Only argon2id is supported.

# TODO

- Give errors and warnings meaningful messages

# Limitations

- This program does not commit to securely wipe sensitive data from memory, such as passwords and cryptography keys.

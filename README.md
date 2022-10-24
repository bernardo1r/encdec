# Simple encryption/decryption tool

This is a simple CLI program to encrypt and decrypt files.

The AEAD used is ChaCha20-Poly1305 and the KDF used is argon2. Only argon2id is supported.

# TODO

- Read and Write files in chunks, allowing files bigger than main memory.

# Limitations

- This program does not commit to securely wipe sensitive data from memory, such as passwords and cryptography keys.

- Since all the file is encrypted in one go, the file size is limited to 256 GB due to ChaCha20 message length restriction (this is only a concern if your computer has that much of RAM anyway).

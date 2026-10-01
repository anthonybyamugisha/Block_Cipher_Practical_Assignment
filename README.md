# CSC 3114: Cryptology and Coding Theory
## Take-Home Assignment — Test 2

This repository contains the group work for **CSC 3114: Cryptology and Coding Theory — Take-Home Assignment (Test 2)**.

The assignment constitutes of practical work on:

- Block ciphers
- DES and AES
- Confusion, diffusion, and avalanche effect
- AES modes of operation
- SHA-256 hashing
- HMAC-SHA256
- Integrity and authentication
- Cryptographic tampering experiments


**Programming language:** Python  
**Final submission:** One PDF per group  

---

# Assignment Structure

The work is divided into five tasks.

## Task 1 — Theory and Cipher Design

This section covers:

- Confusion
- Diffusion
- Avalanche effect
- DES compared with AES
- ECB, CBC, and CTR modes
- Purpose of IVs and nonces
- Common IV/nonce misuse

This task is mainly theoretical and does not require a Python implementation.

---

## Task 2 — AES Avalanche Experiment

AES-128 is used to demonstrate the **avalanche effect**.

The experiment:

1. Encrypts one 16-byte plaintext block.
2. Flips exactly one bit in the plaintext.
3. Encrypts the modified plaintext using the same AES key.
4. Counts how many ciphertext bits change.
5. Repeats the experiment for at least 10 different bit positions.
6. Calculates the average percentage of changed ciphertext bits.

The purpose is to observe how a very small change in plaintext produces a large change in ciphertext.

---

## Task 3 — AES Modes in Practice

The same plaintext message is encrypted and decrypted using:

- AES-CBC
- AES-CTR

CBC uses:

- A fresh IV
- Correct padding

CTR uses:

- A fresh nonce/counter
- No padding requirement

The program verifies that the plaintext recovered after decryption exactly matches the original message.

The IV/nonce and ciphertext lengths are also reported.

---

## Task 4 — Integrity and Tampering

Task 4 demonstrates message integrity and authentication using:

- SHA-256
- HMAC-SHA256

```text
Cryptology and coding theory protect digital communication.
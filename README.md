
# Cryptography

A collection of encryption and decryption algorithm implementations, following the historical development of classical and modern cryptography.

## Sources

* [Frequency Analysis — Cipher Register](https://cipherregister.com/learn/frequency-analysis)
* [Index of Coincidence — Michigan Technological University](https://pages.mtu.edu/~shene/NSF-4/Tutorial/VIG/Vig-IOC.html)
* [Affine Cipher — Arizona State University](https://math.asu.edu/sites/g/files/litvpz216/files/affine.pdf)

## Timeline & Implementation Progress

### Classical Cryptography

* [x] **~1900 BC — Non-standard hieroglyphs**

  * Egypt
  * One of the earliest known examples of deliberately unusual writing.
  * Not primarily intended for cryptographic security.

* [ ] **~500 BC — Scytale**

  * Sparta
  * Transposition cipher.

* [x] **~50 BC — Caesar cipher**

  * Shift substitution cipher.

* [x] **~800 AD — Al-Kindi**

  * Frequency analysis.
  * Historical development in cryptanalysis; not an encryption/decryption algorithm.

* [ ] **1467 — Alberti cipher disk**

  * Early polyalphabetic cipher.
  * Uses multiple substitution alphabets.

* [ ] **1553 — Bellaso cipher**

  * Keyword-based polyalphabetic cipher.
  * Later misattributed to Vigenère.

* [x] **1586 — Vigenère cipher**

  * Polyalphabetic substitution cipher.
  * Uses a repeating keyword to select substitution alphabets.

### Classical Cryptanalysis

* [x] **1863 — Kasiski examination**

  * Cryptanalysis technique for Vigenère-like ciphers.
  * Uses repeated sequences and their spacing to estimate key length.
  * Not an encryption/decryption algorithm.

* [x] **1883 — Kerckhoffs's principle**

  * Security should depend on the secrecy of the key rather than the secrecy of the algorithm.
  * Cryptographic principle rather than an algorithm.

* [x] **1917 — Index of Coincidence**

  * William F. Friedman.
  * Statistical technique for analyzing cipher text.
  * Not an encryption/decryption algorithm.

### Machine Cryptography

* [ ] **1917 — One-time pad**

  * Gilbert Vernam.
  * Encryption scheme providing perfect secrecy when the key is truly random, secret, at least as long as the message, and never reused.

* [ ] **1918 — Enigma**

  * Arthur Scherbius.
  * Rotor-based polyalphabetic cipher machine.

### Modern Cryptography

* [ ] **1970s — DES**

  * Symmetric block cipher.
  * 56-bit effective key size.

* [ ] **1976 — Diffie–Hellman**

  * Public-key key exchange.
  * Establishes a shared secret over an insecure channel.
  * Primarily a key-exchange algorithm rather than an encryption algorithm.

* [ ] **1977 — RSA**

  * Public-key cryptosystem.
  * Supports encryption and decryption based on modular exponentiation and the difficulty of integer factorization.

## Implementation Status

| Algorithm    | Status |
| ------------ | :----: |
| Scytale      |   [ ]  |
| Caesar       |   [x]  |
| Alberti      |   [ ]  |
| Bellaso      |   [ ]  |
| Vigenère     |   [x]  |
| Affine       |   [x]  |
| One-time pad |   [ ]  |
| Enigma       |   [ ]  |
| DES          |   [ ]  |
| RSA          |   [ ]  |

> **Legend:** `[x]` implemented · `[ ]` planned

Used llms, for README, and function naming, double checking algorithms logic.

# Slug20 Library


![Static Badge](https://img.shields.io/badge/%2Fsilene%2Fslug20-libslug-blue?style=flat-square)
![Crates.io Version](https://img.shields.io/crates/v/libslug?style=flat-square)
![Crates.io License](https://img.shields.io/crates/l/libslug?style=flat-square)
![Deps.rs Crate Dependencies (latest)](https://img.shields.io/deps-rs/libslug/latest?style=flat-square)
![Crates.io Total Downloads](https://img.shields.io/crates/d/libslug?style=flat-square)
![Crates.io Dependents](https://img.shields.io/crates/dependents/libslug?style=flat-square)

![Bluesky followers](https://img.shields.io/bluesky/followers/silene0259.bsky.social?link=https%3A%2F%2Fbsky.app%2Fprofile%2Fsilene0259.bsky.social)
![YouTube Channel Subscribers](https://img.shields.io/youtube/channel/subscribers/UCCVb9sS4YjtGlK0oP-9oeig?link=https%3A%2F%2Fwww.youtube.com%2F%40DionysianMyst-u8s)
![X (formerly Twitter) Follow](https://img.shields.io/twitter/follow/jtortorelli09?link=https%3A%2F%2Fx.com%2Fjtortorelli09)
![X (formerly Twitter) Follow](https://img.shields.io/twitter/follow/silene0259?link=https%3A%2F%2Fx.com%2Fsilene0259)

[!["Buy Me A Coffee"](https://img.shields.io/badge/-buy_me_a%C2%A0coffee-gray?logo=buy-me-a-coffee)](https://www.buymeacoffee.com/jtortorelli)





<img height="25%" width="25%" src="https://github.com/sileneundula/libslug20/blob/master/assets/logo/libslug20_logo.png">


## Description

`slug20` is a tool used to encrypt data inspired by **minisign**. It is simple, minimilastic, and has advanced security built-in. It implements `zeroize`, `subtle`, and `subtle-encoding` for maxmimum security.

On top of encryption, it creates a new standard for Modern Certificates using YAML. Its format (`X59CERT`) is lightweight and can easily be serialized.

It extends to include development of modern, decentralized PKI systems and modular formats for use with different systems.

## Features

- **Default Encryption:** ECIES Encryption over Curve25519 using AES-GCM
- **Post-Quantum Encryption:** ML-KEM
- **Signature Schemes:** ED25519, Schnorr over Ristretto (Curve25519), BLS12-381, ECDSA (secp256k1), Ed448
- **Post-Quantum Signature Schemes:** SPHINCS+ (SHAKE256) (Level 5), ML_DSA56 (Level 3), FALCON1024
- **Hybrid Digital Signature Schemes:** EsphandSigning (FALCON1024 + ED25519), ShulginSigning (SPHINCS+ & ED25519), AbsolveSigning (ML-DSA3 + ED25519)
- **Cert Format:** X59 Certificate Standard, PEM
- **Message-Types:** Supports UTF-8 Messages (so we can include emojis)
- **Encryption:** AES-GCM 256 + XChaCha20-Poly1305
- **Randomness Generation:** Supports Randomness Generation from the Operating System. Supports VRFs via Schnorr
- **BIP39:** true, supported
- **BIP32:** still in works

## Table of Contents

1. Symmetric Encryption
2. Public Key Encryption
3. Digital Signing
4. Other

### 1: Symmetric Encryption

- [X] AES256-GCM
- [X] XChaCha20-POLY1305
- [ ] Morus

### 2: Public Key Encryption

- [X] ECIES over ED25519 using SHA3 + AES-GCM
- [X] Kyber

### 3: Digital Signatures

#### 3.1 Hybrid Digital Signature Schemes

- [X] ShulginSigning (SPHINCS+ (SHAKE256) + ED25519)
- [X] EsphandSigning (Falcon1024 + ED25519)
- [X] AbsolveSigning (MLDSA3 + ED25519)

#### 3.2 Classical Signature Schemes

- [X] EdDSA
  - [X] Ed25519
  - [X] Ed448
- [X] ECDSA
  - [X] Secp256k1
- [X] Other
  - [X] BLS12-381
  - [X] Schnorr Over Ristretto

#### 3.3 Post-Quantum Digital Signature Schemes

- [X] SPHINCS+ (SHAKE256) (Level 5)
- [X] FALCON1024
- [X] MLDSA3 (Dilithium65)

#### 4: Other

- [X] BIP39
- [ ] BIP32
- [X] Schnorr VRF
- [X] Cryptographic Randomness
  - [X] SecureRand-rs
  - [X] From_OS
  - [X] Schnorr VRF

## Progress On Signatures

### Classical

- [X] \[Signature] ED25519-dalek
  - [X] Generation
    - [X] OSCSPRNG
    - [X] Securerand-rs
  - [X] Signing
  - [X] Verifying

### Post-Quantum

- [X] \[Signature] FALCON1024
  - [X] Generation
    - [X] OSCSPRNG
  - [X] silene/slugencode
  - [X] Signing
  - [X] Verifying
  - [X] Serialization/Deserialization
  - [X] Zeroize
  - [X] Protocol Info
  - [ ] Derive Public Key From Secret
- [X] \[Signature] SPHINCS+ (SHAKE256) Level 5
  - [X] Generation
    - [X] OSCSPRNG
  - [X] Signing
  - [X] Verifying
  - [X] Serialization/Deserialization
  - [X] Zeroize
  - [ ] Protocol Info
  - [ ] Other
    - [ ] Derive Public Key From Secret  
## X59Registar

X59Registar is a novel project being developed for decentralized public-key infrastructures using the X59CERT format in YAML.

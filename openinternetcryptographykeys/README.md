# OpenInternetCryptographyKeys: A Modern Web 3.20 Cryptography Library With Ease of Access

![Static Badge](https://img.shields.io/badge/WeSpeakInCursive-Silene?style=flat-square&label=OpenInternetCryptographyProject)
![Crates.io Version](https://img.shields.io/crates/v/openinternetcryptographykeys?style=flat-square)
![Crates.io Total Downloads](https://img.shields.io/crates/d/openinternetcryptographykeys?style=flat-square)
![Deps.rs Crate Dependencies (latest)](https://img.shields.io/deps-rs/openinternetcryptographykeys/latest?style=flat-square)
![Crates.io License](https://img.shields.io/crates/l/openinternetcryptographykeys?style=flat-square)
![Crates.io Dependents](https://img.shields.io/crates/dependents/openinternetcryptographykeys?style=flat-square)
![Crates.io Size](https://img.shields.io/crates/size/openinternetcryptographykeys?style=flat-square)
![Crates.io User Total Downloads](https://img.shields.io/crates/udt/253136?style=flat-square)


![Bluesky followers](https://img.shields.io/bluesky/followers/silene0259.bsky.social)



## Description

OpenInternetCryptographyKeys is a crate/library for easy, modern cryptography and abstracts from all the complicated stuff. It is serialized into PEM format.

## Algorithms

- [X] ShulginSigning (SPHINCS+_SHAKE256 & ED25519)
- [X] AbsolveSigning (ML-DSA3 & ED25519)
- [X] EsphandSigning (FALCON1024 & ED25519)
- [ ] ShulginSigningWithEd448
- [ ] AbsolveSigningWithEd448
- [ ] EsphandSigningWithEd448
- [X] ED25519
- [X] ED448
- [X] ECDSA (SECP256k1)
- [X] FALCON1024
- [X] SPHINCS+ (SHAKE256)
- [X] ML-DSA3 (Dilithium65)
- [X] BLS12-381
- [X] Schnorr over Ristretto
- [ ] RSA

## Encryption

- [ ] ECIES-ED25519-SILENE (SHA3)
- [ ] RSA
- [ ] Kyber768

## Serialization

- [X] Standard PEM
- [ ] X59-fmt
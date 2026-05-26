//! # LibSlug Internals
//! 
//! ## TODO
//! 
//! - [ ] Password-Based Encrypt
//! - [ ] ECDSA
//! - [ ] ED448
//! - [ ] RSA
//! - [ ] El-Galmal
//! - [ ] Kyber768

/// Encryption: ECIES (over Curve25519 using SHA3 and AES-GCM) and ML-KEM1024 (Kyber)
pub mod encryption;

/// Symmetric Encryption: XChaCha20-Poly1305, AES256GCM
pub mod encrypt;

#[cfg(feature = "csprng")]
/// SlugCSPRNG: Cryptographically Secure Randomness
pub mod csprng;

#[cfg(feature = "bip39")]
/// Determinstic BIP39
pub mod bip39;

#[cfg(feature = "bip32")]
pub mod bip32;

/// Message Type
pub mod messages;

/// CipherText Type
pub mod ciphertext;

/// Digital Signatures: ED25519, SPHINCS+ (SHAKE256) at 255 bit security
pub mod signature;

/// Digests (Hash Functions)
pub mod digest;

/// Experimental Crypto
pub mod experimental;
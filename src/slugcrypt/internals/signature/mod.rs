//! # LibSlug: Digital Signatures
//! 
//! This module contains all the provided digital signature schemes. A digital signature is a cryptographic signature generated using a secret key, producing a signature that can be verified by the public key of the signer's.
//! 
//! The following are provided:
//! 
//! - [X] ED25519
//! 
//! - [X] Schnorr over Ristreto
//! 
//! - [X] ECDSA (Secp256k1)
//! 
//! - [X] ED448
//! 
//! - [X] BLS12-381
//! 
//! - [X] FALCON1024
//! 
//! - [X] ML-DSA (Dilithium65)
//! 
//! - [X] SPHINCS+ (SHAKE256) (Level 5)
//! 
//! - [ ] Lamport Signatures
//! 
//! - [ ] Winternitz One-Time Signatures (WOTS)
//! 
//! ## Signature Suites
//! 
//! - 0x00: ShulginSigning (Hybrid),
//! - 0x01: EsphandSigning (Hybrid),
//! - 0x02: AbsolveSigning (Hybrid),
//! - 0x03: ED25519 (EdDSA)
//! - 0x04: ED448
//! - 0x05: Secp256k1 (ECDSA)
//! - 0x06: Schnorr over Ristretto
//! - 0x07: BLS12-381
//! - 0x08: Falcon1024
//! - 0x09: SPHINCS+ (SHAKE256)
//! - 0x0A: ML-DSA3 (Dilithium65)
//! 
//! ### 0x00: ShulginSigning: A Hybrid SPHINCS+ (SHAKE256) and ED25519 Signing Scheme
//! 
//! #### Features
//! 
//! - [X] Functionality
//!     - [X] Generating
//!     - [X] Signing
//!     - [X] Verifying
//! 
//! - [X] Encodings
//!     - [X] IntoEncoding
//!     - [X] FromEncoding
//!     - [X] X59
//!         - [X] IntoX59
//!         - [X] FromX59
//!     - [X] PEM
//!         - [X] IntoPem
//!         - [X] FromPem
//! 
//! ## TODO
//! 
//! - [ ] Refactor Hybrid Signatures
//!     - [ ] ShulginSigning
//!     - [ ] EsphandSigning
//!     - [ ] AbsolveSigning
//! - [ ] X59-fmt standard

#[cfg(feature = "sphincs_plus")]
/// SPHINCS+ (SHAKE256) (255bit security) (smaller signature version)
pub mod sphincs_plus;

#[cfg(feature = "ed25519")]
/// ED25519 Signature
pub mod ed25519;

#[cfg(feature = "schnorr")]
/// Schnorr Digital Signature
pub mod schnorr;

#[cfg(feature = "ecdsa")]
/// ECDSA
pub mod ecdsa;

#[cfg(feature = "falcon")]
/// FALCON1024
pub mod falcon;

#[cfg(feature = "ml-dsa")]
/// MLDSA65
pub mod ml_dsa;

#[cfg(feature = "ed448")]

/// ED448 Implementation
pub mod ed448;

/// ShulginSigning (SPHINCS+ & ED25519)
pub mod shulginsigning;

/// EsphandSigning (FALCON1024 & ED25519)
pub mod esphand_signature;

/// PQ Signatures
pub mod standardized;

/// AbsolveSigning
pub mod absolvesigning;

pub mod utils;

pub mod bls;


/// One-Time Signatures (Lamport Signatures, Winternitz-OTS)
#[cfg(feature = "experimental")]
pub mod onetimesigs;

pub mod rsa;

pub mod constants;
//! # OpenInternetCryptographyKeys (OICK or OICPK)
//! 
//! ## Description
//! 
//! Open Internet Cryptography Keys (OICK) is a Rust library for handling cryptographic keys in a standardized way, following the Open Internet Cryptography Key (OICK) specification. It provides functionality for creating, parsing, and managing cryptographic keys, as well as support for various key types and formats.
//! 
//! ## How To Use
//! 
//! You must import the `prelude` module to use the library.
//! 
//! ```rust
//! use openinternetcryptographykeys::prelude::essentials::*;
//! use openinternetcryptographykeys::prelude::essentials::{OpenInternetAPIGeneration, OpenInternetCryptographyKeypair, OpenInternetCryptographySecretKey, OpenInternetFromPemAny, Slug20Algorithm};
//! use openinternetcryptographykeys::prelude::essentials::{OpenInternetSigner,OpenInternetVerifier,OpenInternetPublicKeyDerive,OpenInternetGeneration,OpenInternetAPIGeneration};
//! use openinternetcryptographykeys::prelude::essentials::{OpenInternetFromStandardPEM,OpenInternetIntoStandardPEM};
//! 
//! fn main() {
//! 
//!     // Generate a new ED25519 key
//!     let ed25519 = OpenInternetCryptographySecretKey::generate_with_algorithm(Slug20Algorithm::ED25519);
//!     let ed25519_public = ed25519.public();
//! 
//!     // Sign
//!     let ed25519_signature = ed25519.sign(b"Hello, World!");
//!     
//!     // Verify
//!     let ed25519_verify = ed25519_public.verify(b"Hello, World!", &ed25519_signature);
//!     
//!     // Export To PEM
//!     let ed25519_pem = ed25519.into_standard_pem().unwrap();
//! }
//! 
//! fn shulginsigning() {
//!     // ShulginSigning is a standard for long-term security with small key sizes. Below is the generation of the key.
//!     let shulginsigning = OpenInternetCryptographySecretKey::generate_with_algorithm(Slug20Algorithm::ShulginSigning);
//!     let shulginsigning_public = shulginsigning.public();
//! 
//!     // Sign
//!     let shulginsigning_signature = shulginsigning.sign(b"Hello, World!");
//!     
//!     // Verify
//!     let shulginsigning_verify = shulginsigning_public.verify(b"Hello, World!", &shulginsigning_signature);
//!     
//!     // Export To PEM
//!     let shulginsigning_pem = shulginsigning.into_standard_pem().unwrap();
//! }
//! 
//! 
//! ```
//! 
//! ## Features
//! 
//! - [X] Easy Abstraction For Key Management In Web 3.20
//! - [X] Support for Standardized Key Types
//! - [X] Support for Standardized Key Formats
//! - [X] Support for Standardized Key Derivation
//! - [X] Support for Standardized Key Signatures
//! - [X] Support for Standardized Key Encryption
//! - [X] Zeroize-Support
//! 
//! ## Algorithms Supported
//! 
//! ### Classical
//! 
//! - [X] ED25519 (EdDSA)
//! - [X] ED448 (EdDSA)
//! - [X] SECP256K1 (ECDSA)
//! - [X] BLS12-381 (BLS)
//! - [X] SCHNORR OVER RISTRETTO (Schnorr)
//! - [ ] RSA
//! 
//! ### Post-Quantum
//! 
//! - [X] Falcon
//!     - [ ] Falcon512
//!     - [X] Falcon1024
//! - [X] SLH-DSA (SPHINCS+)
//!     - [X] SLH-DSA-256 using SHAKE256 (Level 5)
//! - [X] ML-DSA (Dilithium)
//!     - [X] ML-DSA3 (Dilithium65)
//! 
//! ### Standardized Hybrids For Web 3.20
//! 
//! - [X] ShulginSigning (SLH-DSA + ED25519) (preferred for long-term security with small key sizes)
//! - [X] EsphandSigning (FALCON1024 + ED25519) (preferred for alternative to ML-DSA3)
//! - [X] AbsolveSigning (ML-DSA3 + ED25519) (preferred for signing with ML-DSA3, where there needs to be standardized security)
//! 
//! ## Encodings
//! 
//! - [X] PEM (preferred for human-readability)
//! - [ ] DER
//! - [ ] JWK
//! - [ ] X59
//! 
//! ## TODO:
//! 
//! - [ ] Add Support For More Algorithms
//! - [ ] Add Support For More Encodings
//! - [ ] Add Support For Key Encryption
//! - [ ] Add Support For Key Wrapping
//! - [ ] Add Support For Key Agreement
//! - [ ] Add Support For Key Exchange
//! - [ ] Add Support For BIP39 Mnemonics
//! - [ ] Add Support For Key Backup and Recovery
//! - [ ] Add Support For Hardware Wallets
//! - [ ] Add Support For More Standardized Hybrids
//! - [ ] Add Support For More Standardized Key Derivation
//! - [ ] Add Support For More Standardized Key Signatures
//! - [ ] Add Support For More Standardized Key Encryption

/// Open Internet Cryptography Keys (OICK) is a Rust library for handling cryptographic keys in a standardized way, following the Open Internet Cryptography Key (OICK) specification. It provides functionality for creating, parsing, and managing cryptographic keys, as well as support for various key types and formats.
pub mod prelude;

/// OpenInternetCryptographyProjectKeys(OICP-KEYS)
pub mod keys;
//! # OpenInternetCryptographyKeysProject (OICKP) - OINT Usage
//! 
//! ## Description
//! 
//! This module provides the implementation for the Open Internet Cryptography Keys (OICK) library, allowing for signing, verifying, key derivation, and generation of keys.
//! 
//! ## Example Usage
//! 
//! ```rust
//! use openinternetcryptographykeys::prelude::essentials::*;
//! use openinternetcryptographykeys::prelude::essentials::{OpenInternetAPIGeneration, OpenInternetCryptographyKeypair, OpenInternetCryptographySecretKey, OpenInternetFromPemAny, Slug20Algorithm};
//! 
//! fn main() {
//! 
//! }
//! 
//! ```
//! 
//! 
//! ## Features
//! 
//! - [X] Generation
//! - [X] Signing
//! - [X] Verifying
//! - [X] Export As Pem
//! - [X] Import From Pem
//! - [ ] Alternative Exports
//! - [ ] Address Deriviation
//! 
//! ## Algorithms
//! 
//! - [X] ShulginSigning (ED25519 + SPHINCS+ using SHAKE256)
//! - [X] EsphandSigning (ED25519 + FALCON1024)
//! - [X] AbsolveSigning (ED25519 + ML-DSA3)
//! - [X] ED25519
//! - [X] ED448
//! - [X] SCHNORR
//! - [X] BLS12-381
//! - [X] SLH-DSA5 (SPHINCS+ using SHAKE256)
//! - [X] ML-DSA3 (Dilithium65)
//! - [X] FALCON1024
//! 
//! ## Info
//! 
//! ### Standards
//! 
//! **Context For Signing:** `OpenInternetCryptographyStandardContext`
use fixedstr::str192;
use libslug::errors::SlugErrors;
use libslug::prelude::SlugSphincsPlus;
use libslug::slugcrypt::internals::ciphertext::CipherText;
use libslug::slugcrypt::internals::encryption::ecies::ECIESEncrypt;
use libslug::slugcrypt::internals::signature::bls;
use libslug::slugcrypt::traits::IntoStandardPem;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::prelude::essentials::{OpenInternetGeneration,OpenInternetSigner,OpenInternetVerifier,OpenInternetPublicKeyDerive};
use crate::prelude::essentials::Slug20Algorithm;
use crate::prelude::essentials::{Slug20PublicKey,Slug20SecretKey, Slug20Signature};
use crate::prelude::essentials::{OpenInternetFromStandardPEM,OpenInternetIntoStandardPEM}; //OpenInternetIntoStandardPEM

use libslug::slugcrypt::traits::{IntoBincode,FromBincode};
use libslug::slugcrypt::traits::FromStandardPem;
use crate::keys::oint::required_traits::{OpenInternetAPIGeneration, OpenInternetFromPemAny};
use crate::keys::oint::__types::{FromPemAny, Slug20EncryptionPublicKey, Slug20EncryptionSecretKey, Slug20KeyType};
use crate::keys::oint::__types::PemEncodingSuites;


use libslug::slugcrypt::internals::signature::{
    shulginsigning::{ShulginKeypair,ShulginSignature},
    absolvesigning::{AbsolveKeypair,AbsolveSignature},
    esphand_signature::{EsphandKeypair,EsphandSignature},
    ed25519::{ED25519PublicKey,ED25519SecretKey,ED25519Signature},
    ed448::{Ed448PublicKey,Ed448SecretKey,Ed448Signature},
    ecdsa::{ECDSAPublicKey, ECDSASecretKey, ECDSASignature},
    falcon::{Falcon1024PublicKey,Falcon1024SecretKey,Falcon1024Signature},
    ml_dsa::{MLDSA3PublicKey, MLDSA3SecretKey, MLDSA3Signature},
    schnorr::{SchnorrPublicKey, SchnorrSecretKey, SchnorrSignature},
    sphincs_plus::{SPHINCSPublicKey, SPHINCSSecretKey, SPHINCSSignature},
    bls::{BLSPublicKey, BLSSecretKey, BLSSignature}
};

use libslug::slugcrypt::internals::signature::falcon::SlugFalcon1024;
use libslug::slugcrypt::internals::signature::ml_dsa::SlugMLDSA3;

pub const OpenInternetCryptographyStandardContext: &[u8] = b"OpenInternetCryptographyStandardContext";

//=====OPENINTERNETCRYPTOGRAPHYKEYS OINT TYPES=====

/// # Open Internet Cryptography Keys (OICK) - OINT Types
/// 
/// This module defines the core types for the Open Internet Cryptography Keys (OICK) library, specifically for the OINT (Open Internet Cryptography Key) cipher suite. It includes standardized key and signature types, as well as a structure for representing cipher suites and their variants.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Hash,Zeroize, ZeroizeOnDrop)]
pub struct OpenInternetCryptographyPublicKey {
    pub key: Box<Slug20PublicKey>,
}

/// # Open Internet Cryptography Keys (OICK) - OINT Types
/// 
/// This module defines the core types for the Open Internet Cryptography Keys (OICK) library, specifically for the OINT (Open Internet Cryptography Key) cipher suite. It includes standardized key and signature types, as well as a structure for representing cipher suites and their variants.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Hash,Zeroize, ZeroizeOnDrop)]
pub struct OpenInternetCryptographySecretKey {
    pub key: Box<Slug20SecretKey>,
}

/// # Open Internet Cryptography Keys (OICK) - OINT Types
/// 
/// This module defines the core types for the Open Internet Cryptography Keys (OICK) library, specifically for the OINT (Open Internet Cryptography Key) cipher suite. It includes standardized key and signature types, as well as a structure for representing cipher suites and their variants.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Hash,Zeroize, ZeroizeOnDrop)]
pub struct OpenInternetCryptographySignature {
    pub signature: Box<Slug20Signature>,
}

/// # Open Internet Cryptography Keypair
/// 
/// This struct represents a keypair consisting of a public key and a secret key for the Open Internet Cryptography Keys (OICK) library, specifically for the OINT (Open Internet Cryptography Key) cipher suite.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Hash,Zeroize, ZeroizeOnDrop)]
pub struct OpenInternetCryptographyKeypair {
    pub public_key: OpenInternetCryptographyPublicKey,
    pub secret_key: OpenInternetCryptographySecretKey,
}

//=====OPENINTERNETCRYPTOGRAPHYKEYS OINT CIPHER SUITE=====

#[derive(Serialize, Copy, Deserialize, Debug, Clone, PartialEq, PartialOrd, Hash)]
pub struct OpenInternetCryptographyCipherSuite {
    pub cipher_suite: str192,
    pub variant: Option<str192>,
}

pub struct OpenInternetCryptographyAPI;

//=====OPENINTERNETCRYPTOGRAPHYKEYS OINT USAGE=====

//=====IMPLEMENTATION MANUAL=====//
impl OpenInternetCryptographyPublicKey {
    pub fn from_slug20_public_key(key: Slug20PublicKey) -> Self {
        OpenInternetCryptographyPublicKey { key: Box::new(key) as Box<Slug20PublicKey> }
    }
}

impl OpenInternetCryptographySecretKey {
    pub fn from_slug20_secret_key(key: Slug20SecretKey) -> Self {
        OpenInternetCryptographySecretKey { key: Box::new(key) as Box<Slug20SecretKey> }
    }
}

impl OpenInternetCryptographySignature {
    pub fn from_slug20_signature(signature: Slug20Signature) -> Self {
        OpenInternetCryptographySignature { signature: Box::new(signature) as Box<Slug20Signature> }
    }
}

impl OpenInternetCryptographyKeypair {
    pub fn from_slug20_keypair(public_key: Slug20PublicKey, secret_key: Slug20SecretKey) -> Self {
        OpenInternetCryptographyKeypair {
            public_key: OpenInternetCryptographyPublicKey::from_slug20_public_key(public_key),
            secret_key: OpenInternetCryptographySecretKey::from_slug20_secret_key(secret_key),
        }
    }
    pub fn into_public_key(&self) -> OpenInternetCryptographyPublicKey {
        self.public_key.clone()
    }
    pub fn into_secret_key(&self) -> OpenInternetCryptographySecretKey {
        self.secret_key.clone()
    }
    pub fn as_public_key(&self) -> &OpenInternetCryptographyPublicKey {
        &self.public_key
    }
    pub fn as_secret_key(&self) -> &OpenInternetCryptographySecretKey {
        &self.secret_key
    }
    pub fn algorithm(&self) -> Slug20Algorithm {
        match &*self.public_key.key {
            Slug20PublicKey::ShulginSigning(_) => Slug20Algorithm::ShulginSigning,
            Slug20PublicKey::AbsolveSigning(_) => Slug20Algorithm::AbsolveSigning,
            Slug20PublicKey::EsphandSigning(_) => Slug20Algorithm::EsphandSigning,
            Slug20PublicKey::BLS(_) => Slug20Algorithm::BLS,
            Slug20PublicKey::ECDSA(_) => Slug20Algorithm::ECDSA,
            Slug20PublicKey::Ed25519(_) => Slug20Algorithm::Ed25519,
            Slug20PublicKey::Ed448(_) => Slug20Algorithm::Ed448,
            Slug20PublicKey::Falcon(_) => Slug20Algorithm::Falcon,
            Slug20PublicKey::MLDSA(_) => Slug20Algorithm::MLDSA,
            Slug20PublicKey::Schnorr(_) => Slug20Algorithm::Schnorr,
            Slug20PublicKey::SPHINCSPlus(_) => Slug20Algorithm::SPHINCSPlus,
        }
    }
}

//=====IMPLEMENTATION OF OINT USAGE TYPES=====

impl OpenInternetGeneration for OpenInternetCryptographySecretKey {
    fn generate_with_algorithm(alg: Slug20Algorithm) -> Result<Self, libslug::prelude::core::SlugErrors> {
        match alg {
            Slug20Algorithm::ShulginSigning => {
                let keypair: ShulginKeypair = ShulginKeypair::generate();
                Ok(OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::ShulginSigning(Box::new(keypair))))
            },
            Slug20Algorithm::AbsolveSigning => {
                let keypair: AbsolveKeypair = AbsolveKeypair::generate();
                Ok(OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::AbsolveSigning(Box::new(keypair))))
            },
            Slug20Algorithm::EsphandSigning => {
                let keypair: EsphandKeypair = EsphandKeypair::generate();
                Ok(OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::EsphandSigning(Box::new(keypair))))
            },
            Slug20Algorithm::Ed25519 => {
                let secret_key: ED25519SecretKey = ED25519SecretKey::generate();
                Ok(OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::Ed25519(secret_key)))
            },
            Slug20Algorithm::Ed448 => {
                let secret_key: Ed448SecretKey = Ed448SecretKey::generate();
                Ok(OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::Ed448(secret_key)))
            },
            Slug20Algorithm::ECDSA => {
                let secret_key: ECDSASecretKey = ECDSASecretKey::generate();
                Ok(OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::ECDSA(secret_key)))
            },
            Slug20Algorithm::Falcon => {
                let (pk,sk): (Falcon1024PublicKey, Falcon1024SecretKey) = SlugFalcon1024::generate();
                Ok(OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::Falcon(Box::new(sk))))
            },
            Slug20Algorithm::MLDSA => {
                let secret_key: libslug::slugcrypt::internals::signature::ml_dsa::MLDSA3Keypair = SlugMLDSA3::generate();
                Ok(OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::MLDSA(Box::new(secret_key.secret_key.clone()))))
            },
            Slug20Algorithm::Schnorr => {
                let secret_key: SchnorrSecretKey = SchnorrSecretKey::generate();
                Ok(OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::Schnorr(secret_key)))
            },
            Slug20Algorithm::SPHINCSPlus => {
                let secret_key: (SPHINCSPublicKey, SPHINCSSecretKey) = SPHINCSSecretKey::generate();
                Ok(OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::SPHINCSPlus(secret_key.1))) 
            },
            Slug20Algorithm::BLS => {
                let secret_key = BLSSecretKey::generate();
                Ok(OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::BLS(secret_key)))
            },
        }
    }
}

impl OpenInternetSigner for OpenInternetCryptographySecretKey {
    fn sign_with_context<T: AsRef<[u8]>>(&self, message: T, context: T) -> Result<OpenInternetCryptographySignature, SlugErrors> {
        match &*self.key {
            Slug20SecretKey::ShulginSigning(keypair) => {
                let signature: ShulginSignature = keypair.sign(message)?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::ShulginSigning(Box::new(signature))))
            },
            // TODO: Context Parsing; Should support keeping context in struct
            Slug20SecretKey::AbsolveSigning(keypair) => {
                let signature: AbsolveSignature = keypair.sign_with_context(message, context)?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::AbsolveSigning(Box::new(signature))))
            },
            Slug20SecretKey::EsphandSigning(keypair) => {
                let signature: EsphandSignature = keypair.sign(message)?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::EsphandSigning(Box::new(signature))))
            },
            Slug20SecretKey::BLS(key) => {
                let signature: BLSSignature = key.sign(message)?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::BLS(signature)))
             },
            Slug20SecretKey::ECDSA(key) => {
                let signature: (ECDSASignature, libslug::slugcrypt::internals::signature::ecdsa::ECDSASignatureRecoveryID) = key.sign(message)?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::ECDSA(signature.0)))
             },
            Slug20SecretKey::Ed25519(key) => {
                let signature: ED25519Signature = key.sign(message)?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::Ed25519(signature)))
            },
            Slug20SecretKey::Ed448(key) => {
                let signature: Ed448Signature = key.sign(message)?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::Ed448(signature)))
            }
            Slug20SecretKey::Falcon(key) => {
                let signature = key.sign(message);

                if signature.is_err() {
                    return Err(libslug::prelude::core::SlugErrors::Other(String::from("Signing with Falcon failed")));
                }
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::Falcon(Box::new(signature.unwrap()))))
            },
            Slug20SecretKey::MLDSA(key) => {
                let signature: MLDSA3Signature = key.sign(message, context)?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::MLDSA(Box::new(signature))))
            },
            Slug20SecretKey::Schnorr(key) => {
                let signature = key.sign_with_context(message, context);

                if signature.is_err() {
                    return Err(libslug::prelude::core::SlugErrors::Other(String::from("Signing with Schnorr failed")));
                }
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::Schnorr(signature.unwrap())))
            },
            Slug20SecretKey::SPHINCSPlus(key) => {
                let signature: SPHINCSSignature = key.sign(message)?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::SPHINCSPlus(Box::new(signature))))
            },
            _ => Err(libslug::prelude::core::SlugErrors::Other(String::from("Unsupported algorithm for signing with context")))
        }
    }
    fn sign<T: AsRef<[u8]>>(&self, message: T) -> Result<OpenInternetCryptographySignature, SlugErrors> {
        self.sign_with_context(message.as_ref(), OpenInternetCryptographyStandardContext)
    }
}

impl OpenInternetVerifier for OpenInternetCryptographyPublicKey {
    fn verify_with_context<T: AsRef<[u8]>>(&self, message: T, context: T, signature: &OpenInternetCryptographySignature) -> Result<bool, SlugErrors> {
        match &*self.key {
            Slug20PublicKey::ShulginSigning(keypair) => {
                if let Slug20Signature::ShulginSigning(sig) = &*signature.signature {
                    keypair.verify(message.as_ref(), sig)
                } else {
                    Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for ShulginSigning")))
                }
            },
            Slug20PublicKey::AbsolveSigning(keypair) => {
                if let Slug20Signature::AbsolveSigning(sig) = &*signature.signature {
                    keypair.verify(message.as_ref(), *sig.to_owned())
                } else {
                    Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for AbsolveSigning")))
                }
            },
            Slug20PublicKey::EsphandSigning(keypair) => {
                if let Slug20Signature::EsphandSigning(sig) = &*signature.signature {
                    keypair.verify(message, sig)
                } else {
                    Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for EsphandSigning")))
                }
            },
            Slug20PublicKey::BLS(key) => {
                if let Slug20Signature::BLS(sig) = &*signature.signature {
                    key.verify(message, sig)
                } else {
                    Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for BLS")))
                }
             },
            Slug20PublicKey::ECDSA(key) => {
                if let Slug20Signature::ECDSA(sig) = &*signature.signature {
                    key.verify(message, sig.clone())
                } else {
                    Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for ECDSA")))
                }
             },
            Slug20PublicKey::Ed25519(key) => {
                if let Slug20Signature::Ed25519(sig) = &*signature.signature {
                    let x = key.verify(sig.to_owned(), message.as_ref())?;
                    return Ok(x)
                } else {
                    Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for Ed25519")))
                }
            },
            Slug20PublicKey::Ed448(key) => {
                if let Slug20Signature::Ed448(sig) = &*signature.signature {
                    key.verify(message, sig.clone())
                } else {
                    Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for Ed448")))
                }
            }
            Slug20PublicKey::Falcon(key) => {
                if let Slug20Signature::Falcon(sig) = &*signature.signature {
                    let x = key.verify(message, sig);

                    if x.is_err() {
                        return Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for Falcon")));
                    }
                    return Ok(x.unwrap())
                } else {
                    Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for Falcon")))
                }
            },
            Slug20PublicKey::MLDSA(key) => {
                if let Slug20Signature::MLDSA(sig) = &*signature.signature {
                    let x = key.verify(message.as_ref(), context.as_ref(), sig);
                    if x.is_err() {
                        return Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for MLDSA")));
                    }
                    return Ok(x.unwrap())
                } else {
                    Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for MLDSA")))
                }
            },
            Slug20PublicKey::Schnorr(key) => {
                if let Slug20Signature::Schnorr(sig) = &*signature.signature {
                    let x = key.verify_with_context(message, context, sig.clone());
                    if x.is_err() {
                        return Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for Schnorr")));
                    }
                    else {
                        return Ok(true)
                    }
                } else {
                    Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for Schnorr")))
                }
            },
            Slug20PublicKey::SPHINCSPlus(key) => {
                if let Slug20Signature::SPHINCSPlus(sig) = &*signature.signature {
                    let x = key.verify(message, *sig.clone());

                    if x.is_err() {
                        return Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for SPHINCSPlus")));
                    }
                    else {
                        return Ok(true)
                    }
                } else {
                    Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for SPHINCSPlus")))
                }
            },
            _ => Err(libslug::prelude::core::SlugErrors::Other(String::from("Unsupported algorithm for verification with context")))
        }
    }
    fn verify<T: AsRef<[u8]>>(&self, message: T, signature: &OpenInternetCryptographySignature) -> Result<bool, SlugErrors> {
        self.verify_with_context(message.as_ref(), OpenInternetCryptographyStandardContext, signature)
    }
}

// TODO: Keypairs
impl OpenInternetIntoStandardPEM for OpenInternetCryptographySecretKey {
    fn into_standard_pem(&self) -> Result<String, SlugErrors> {
        match &*self.key {
            Slug20SecretKey::ShulginSigning(keypair) => keypair.into_standard_pem(),
            Slug20SecretKey::AbsolveSigning(keypair) => keypair.into_standard_pem(),
            Slug20SecretKey::EsphandSigning(keypair) => keypair.into_standard_pem(),
            Slug20SecretKey::BLS(key) => key.into_standard_pem(),
            Slug20SecretKey::ECDSA(key) => key.into_standard_pem(),
            Slug20SecretKey::Ed25519(key) => key.into_standard_pem(),
            Slug20SecretKey::Ed448(key) => key.into_standard_pem(),
            Slug20SecretKey::Falcon(key) => key.into_standard_pem(),
            Slug20SecretKey::MLDSA(key) => key.into_standard_pem(),
            Slug20SecretKey::Schnorr(key) => key.into_standard_pem(),
            Slug20SecretKey::SPHINCSPlus(key) => key.into_standard_pem(),
        }
    }
    fn as_standard_pem_label(&self) -> String {
        match &*self.key {
            Slug20SecretKey::ShulginSigning(keypair) => ShulginKeypair::label_for_standard_pem_secret(),
            Slug20SecretKey::AbsolveSigning(keypair) => AbsolveKeypair::label_for_standard_pem_secret(),
            Slug20SecretKey::EsphandSigning(keypair) => EsphandKeypair::label_for_standard_pem_secret(),
            Slug20SecretKey::BLS(key) => BLSSecretKey::label_for_standard_pem_secret(),
            Slug20SecretKey::ECDSA(key) => ECDSASecretKey::label_for_standard_pem_secret(),
            Slug20SecretKey::Ed25519(key) => ED25519SecretKey::label_for_standard_pem_secret(),
            Slug20SecretKey::Ed448(key) => Ed448SecretKey::label_for_standard_pem_secret(),
            Slug20SecretKey::Falcon(key) => Falcon1024SecretKey::label_for_standard_pem_secret(),
            Slug20SecretKey::MLDSA(key) => MLDSA3SecretKey::label_for_standard_pem_secret(),
            Slug20SecretKey::Schnorr(key) => SchnorrSecretKey::label_for_standard_pem_secret(),
            Slug20SecretKey::SPHINCSPlus(key) => SPHINCSSecretKey::label_for_standard_pem_secret(),
        }
    }
}

impl OpenInternetIntoStandardPEM for OpenInternetCryptographyPublicKey {
    fn into_standard_pem(&self) -> Result<String, SlugErrors> {
        match &*self.key {
            Slug20PublicKey::ShulginSigning(keypair) => keypair.into_standard_pem(),
            Slug20PublicKey::AbsolveSigning(keypair) => keypair.into_standard_pem(),
            Slug20PublicKey::EsphandSigning(keypair) => keypair.into_standard_pem(),
            Slug20PublicKey::BLS(key) => key.into_standard_pem(),
            Slug20PublicKey::ECDSA(key) => key.into_standard_pem(),
            Slug20PublicKey::Ed25519(key) => key.into_standard_pem(),
            Slug20PublicKey::Ed448(key) => key.into_standard_pem(),
            Slug20PublicKey::Falcon(key) => key.into_standard_pem(),
            Slug20PublicKey::MLDSA(key) => key.into_standard_pem(),
            Slug20PublicKey::Schnorr(key) => key.into_standard_pem(),
            Slug20PublicKey::SPHINCSPlus(key) => key.into_standard_pem(),
        }
    }
    fn as_standard_pem_label(&self) -> String {
        match &*self.key {
            Slug20PublicKey::ShulginSigning(keypair) => ShulginKeypair::label_for_standard_pem(),
            Slug20PublicKey::AbsolveSigning(keypair) => AbsolveKeypair::label_for_standard_pem(),
            Slug20PublicKey::EsphandSigning(keypair) => EsphandKeypair::label_for_standard_pem(),
            Slug20PublicKey::BLS(key) => BLSPublicKey::label_for_standard_pem(),
            Slug20PublicKey::ECDSA(key) => ECDSAPublicKey::label_for_standard_pem(),
            Slug20PublicKey::Ed25519(key) => ED25519PublicKey::label_for_standard_pem(),
            Slug20PublicKey::Ed448(key) => Ed448PublicKey::label_for_standard_pem(),
            Slug20PublicKey::Falcon(key) => Falcon1024PublicKey::label_for_standard_pem(),
            Slug20PublicKey::MLDSA(key) => MLDSA3PublicKey::label_for_standard_pem(),
            Slug20PublicKey::Schnorr(key) => SchnorrPublicKey::label_for_standard_pem(),
            Slug20PublicKey::SPHINCSPlus(key) => SPHINCSPublicKey::label_for_standard_pem(),
        }
    }
}
impl OpenInternetIntoStandardPEM for OpenInternetCryptographySignature {
    fn into_standard_pem(&self) -> Result<String, SlugErrors> {
        match &*self.signature {
            Slug20Signature::ShulginSigning(sig) => sig.into_standard_pem(),
            Slug20Signature::AbsolveSigning(sig) => sig.into_standard_pem(),
            Slug20Signature::EsphandSigning(sig) => sig.into_standard_pem(),
            Slug20Signature::BLS(sig) => sig.into_standard_pem(),
            Slug20Signature::ECDSA(sig) => sig.into_standard_pem(),
            Slug20Signature::Ed25519(sig) => sig.into_standard_pem(),
            Slug20Signature::Ed448(sig) => sig.into_standard_pem(),
            Slug20Signature::Falcon(sig) => sig.into_standard_pem(),
            Slug20Signature::MLDSA(sig) => sig.into_standard_pem(),
            Slug20Signature::Schnorr(sig) => sig.into_standard_pem(),
            Slug20Signature::SPHINCSPlus(sig) => sig.into_standard_pem(),
        }
    }
    fn as_standard_pem_label(&self) -> String {
        match &*self.signature {
            Slug20Signature::ShulginSigning(sig) => ShulginSignature::label_for_standard_pem(),
            Slug20Signature::AbsolveSigning(sig) => AbsolveSignature::label_for_standard_pem(),
            Slug20Signature::EsphandSigning(sig) => EsphandSignature::label_for_standard_pem(),
            Slug20Signature::BLS(sig) => BLSSignature::label_for_standard_pem(),
            Slug20Signature::ECDSA(sig) => ECDSASignature::label_for_standard_pem(),
            Slug20Signature::Ed25519(sig) => ED25519Signature::label_for_standard_pem(),
            Slug20Signature::Ed448(sig) => Ed448Signature::label_for_standard_pem(),
            Slug20Signature::Falcon(sig) => Falcon1024Signature::label_for_standard_pem(),
            Slug20Signature::MLDSA(sig) => MLDSA3Signature::label_for_standard_pem(),
            Slug20Signature::Schnorr(sig) => SchnorrSignature::label_for_standard_pem(),
            Slug20Signature::SPHINCSPlus(sig) => SPHINCSSignature::label_for_standard_pem(),
        }
    }
}



impl OpenInternetFromStandardPEM for OpenInternetCryptographySecretKey {
    fn from_standard_pem_with_algorithm<T: AsRef<str>>(pem: T, alg: Slug20Algorithm) -> Result<Self, SlugErrors> {
        match alg {
            Slug20Algorithm::ShulginSigning => {
                let keypair: ShulginKeypair = ShulginKeypair::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::ShulginSigning(Box::new(keypair))))
            },
            Slug20Algorithm::AbsolveSigning => {
                let keypair: AbsolveKeypair = AbsolveKeypair::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::AbsolveSigning(Box::new(keypair))))
            },
            Slug20Algorithm::EsphandSigning => {
                let keypair: EsphandKeypair = EsphandKeypair::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::EsphandSigning(Box::new(keypair))))
            },
            Slug20Algorithm::Ed25519 => {
                let secret_key: ED25519SecretKey = ED25519SecretKey::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::Ed25519(secret_key)))
            },
            Slug20Algorithm::Ed448 => {
                let secret_key: Ed448SecretKey = Ed448SecretKey::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::Ed448(secret_key)))
            },
            Slug20Algorithm::ECDSA => {
                let secret_key: ECDSASecretKey = ECDSASecretKey::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::ECDSA(secret_key)))
            },
            Slug20Algorithm::Falcon => {
                let secret_key: Falcon1024SecretKey = Falcon1024SecretKey::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::Falcon(Box::new(secret_key))))
            },
            Slug20Algorithm::MLDSA => {
                let secret_key: MLDSA3SecretKey = MLDSA3SecretKey::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::MLDSA(Box::new(secret_key))))
            },
            Slug20Algorithm::Schnorr => {
                let secret_key: SchnorrSecretKey = SchnorrSecretKey::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::Schnorr(secret_key)))
            },
            Slug20Algorithm::SPHINCSPlus => {
                let secret_key: SPHINCSSecretKey = SPHINCSSecretKey::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::SPHINCSPlus(secret_key)))
            },
            Slug20Algorithm::BLS => {
                let secret_key: BLSSecretKey = BLSSecretKey::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::BLS(secret_key)))
            },
        }
    }
    /*
    fn from_standard_pem<T: AsRef<str>>(pem: T) {

        for x in Self::enumerate_standard_pem_labels() {
            if pem.as_ref().contains(x.as_str()) {
                match x {
                    Slug20SecretKey::AbsolveSigning(x) => {
                        
                    }
                }
            }
        }
        if pem.as_ref().contains()
        */
        
        //OpenInternetCryptographySecretKey::from_standard_pem_with_algorithm(pem, alg)
    //}
    fn get_standard_pem_label_with_algorithm(alg: Slug20Algorithm) -> String {
        match alg {
            Slug20Algorithm::AbsolveSigning => AbsolveKeypair::label_for_standard_pem_secret(),
            Slug20Algorithm::EsphandSigning => EsphandKeypair::label_for_standard_pem_secret(),
            Slug20Algorithm::ShulginSigning => ShulginKeypair::label_for_standard_pem_secret(),
            Slug20Algorithm::Ed25519 => ED25519SecretKey::label_for_standard_pem_secret(),
            Slug20Algorithm::Ed448 => Ed448SecretKey::label_for_standard_pem_secret(),
            Slug20Algorithm::ECDSA => ECDSASecretKey::label_for_standard_pem_secret(),
            Slug20Algorithm::Falcon => Falcon1024SecretKey::label_for_standard_pem_secret(),
            Slug20Algorithm::MLDSA => MLDSA3SecretKey::label_for_standard_pem_secret(),
            Slug20Algorithm::Schnorr => SchnorrSecretKey::label_for_standard_pem_secret(),
            Slug20Algorithm::SPHINCSPlus => SPHINCSSecretKey::label_for_standard_pem_secret(),
            Slug20Algorithm::BLS => BLSSecretKey::label_for_standard_pem_secret(),
        }
    }
    fn enumerate_standard_pem_labels() -> Vec<String> {
        vec![
            Self::get_standard_pem_label_with_algorithm(Slug20Algorithm::ShulginSigning),
            Self::get_standard_pem_label_with_algorithm(Slug20Algorithm::AbsolveSigning),
            Self::get_standard_pem_label_with_algorithm(Slug20Algorithm::EsphandSigning),
            Self::get_standard_pem_label_with_algorithm(Slug20Algorithm::Ed25519),
            Self::get_standard_pem_label_with_algorithm(Slug20Algorithm::Ed448),
            Self::get_standard_pem_label_with_algorithm(Slug20Algorithm::ECDSA),
            Self::get_standard_pem_label_with_algorithm(Slug20Algorithm::Falcon),
            Self::get_standard_pem_label_with_algorithm(Slug20Algorithm::MLDSA),
            Self::get_standard_pem_label_with_algorithm(Slug20Algorithm::Schnorr),
            Self::get_standard_pem_label_with_algorithm(Slug20Algorithm::SPHINCSPlus),
            Self::get_standard_pem_label_with_algorithm(Slug20Algorithm::BLS),
        ]
    }
    fn get_standard_pem_label(&self) -> String {
        return String::from("Test")
    }
}

impl OpenInternetFromStandardPEM for OpenInternetCryptographyPublicKey {
    fn from_standard_pem_with_algorithm<T: AsRef<str>>(pem: T, alg: Slug20Algorithm) -> Result<Self, SlugErrors> {
        match alg {
            Slug20Algorithm::ShulginSigning => {
                let x = ShulginKeypair::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::ShulginSigning(Box::new(x))))
            },
            Slug20Algorithm::AbsolveSigning => {
                let x = AbsolveKeypair::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::AbsolveSigning(Box::new(x))))
            },
            Slug20Algorithm::EsphandSigning => {
                let x = EsphandKeypair::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::EsphandSigning(Box::new(x))))
            }
            Slug20Algorithm::BLS => {
                let x = BLSPublicKey::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::BLS(x)))
            }
            Slug20Algorithm::ECDSA => {
                let x = ECDSAPublicKey::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::ECDSA(x)))
            }
            Slug20Algorithm::Ed25519 => {
                let x = ED25519PublicKey::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::Ed25519(x)))
            }
            Slug20Algorithm::Ed448 => {
                let x = Ed448PublicKey::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::Ed448(x)))
            }
            Slug20Algorithm::Falcon => {
                let x = Falcon1024PublicKey::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::Falcon(Box::new(x))))
            }
            Slug20Algorithm::MLDSA => {
                let x = MLDSA3PublicKey::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::MLDSA(Box::new(x))))
            }
            Slug20Algorithm::Schnorr => {
                let x = SchnorrPublicKey::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::Schnorr(x)))
            }
            Slug20Algorithm::SPHINCSPlus => {
                let x = SPHINCSPublicKey::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::SPHINCSPlus(x)))
            }
            _ => panic!("OpenInternetCryptographyPublicKey::from_standard_pem_with_algorithm: algorithm not supported"),
        }
    }
    fn get_standard_pem_label_with_algorithm(alg: Slug20Algorithm) -> String {
        match alg {
            Slug20Algorithm::ShulginSigning => ShulginKeypair::label_for_standard_pem(),
            Slug20Algorithm::AbsolveSigning => AbsolveKeypair::label_for_standard_pem(),
            Slug20Algorithm::EsphandSigning => EsphandKeypair::label_for_standard_pem(),
            Slug20Algorithm::BLS => BLSPublicKey::label_for_standard_pem(),
            Slug20Algorithm::ECDSA => ECDSAPublicKey::label_for_standard_pem(),
            Slug20Algorithm::Ed25519 => ED25519PublicKey::label_for_standard_pem(),
            Slug20Algorithm::Ed448 => Ed448PublicKey::label_for_standard_pem(),
            Slug20Algorithm::Falcon => Falcon1024PublicKey::label_for_standard_pem(),
            Slug20Algorithm::MLDSA => MLDSA3PublicKey::label_for_standard_pem(),
            Slug20Algorithm::Schnorr => SchnorrPublicKey::label_for_standard_pem(),
            Slug20Algorithm::SPHINCSPlus => SPHINCSPublicKey::label_for_standard_pem(),
            _ => panic!("OpenInternetCryptographyPublicKey::get_standard_pem_label_with_algorithm: algorithm not supported"),
        }
    }
    fn get_standard_pem_label(&self) -> String {
        match &*self.key {
            Slug20PublicKey::ShulginSigning(x) => ShulginKeypair::label_for_standard_pem(),
            Slug20PublicKey::AbsolveSigning(x) => AbsolveKeypair::label_for_standard_pem(),
            Slug20PublicKey::EsphandSigning(x) => EsphandKeypair::label_for_standard_pem(),
            Slug20PublicKey::BLS(x) => BLSPublicKey::label_for_standard_pem(),
            Slug20PublicKey::ECDSA(x) => ECDSAPublicKey::label_for_standard_pem(),
            Slug20PublicKey::Ed25519(x) => ED25519PublicKey::label_for_standard_pem(),
            Slug20PublicKey::Ed448(x) => Ed448PublicKey::label_for_standard_pem(),
            Slug20PublicKey::Falcon(x) => Falcon1024PublicKey::label_for_standard_pem(),
            Slug20PublicKey::MLDSA(x) => MLDSA3PublicKey::label_for_standard_pem(),
            Slug20PublicKey::Schnorr(x) => SchnorrPublicKey::label_for_standard_pem(),
            Slug20PublicKey::SPHINCSPlus(x) => SPHINCSPublicKey::label_for_standard_pem(),
        }  
    }
    fn enumerate_standard_pem_labels() -> Vec<String> {
        vec![
            ShulginKeypair::label_for_standard_pem(),
            AbsolveKeypair::label_for_standard_pem(),
            EsphandKeypair::label_for_standard_pem(),
            BLSPublicKey::label_for_standard_pem(),
            ECDSAPublicKey::label_for_standard_pem(),
            ED25519PublicKey::label_for_standard_pem(),
            Ed448PublicKey::label_for_standard_pem(),
            Falcon1024PublicKey::label_for_standard_pem(),
            MLDSA3PublicKey::label_for_standard_pem(),
            SchnorrPublicKey::label_for_standard_pem(),
            SPHINCSPublicKey::label_for_standard_pem(),
        ]
    }
}

impl OpenInternetFromStandardPEM for OpenInternetCryptographySignature {
    fn enumerate_standard_pem_labels() -> Vec<String> {
        vec![
            ShulginSignature::label_for_standard_pem(),
            AbsolveSignature::label_for_standard_pem(),
            EsphandSignature::label_for_standard_pem(),
            BLSSignature::label_for_standard_pem(),
            ECDSASignature::label_for_standard_pem(),
            ED25519Signature::label_for_standard_pem(),
            Ed448Signature::label_for_standard_pem(),
            Falcon1024Signature::label_for_standard_pem(),
            MLDSA3Signature::label_for_standard_pem(),
            SchnorrSignature::label_for_standard_pem(),
            SPHINCSSignature::label_for_standard_pem(),
        ]
    }
    fn from_standard_pem_with_algorithm<T: AsRef<str>>(pem: T, alg: Slug20Algorithm) -> Result<Self, SlugErrors> {
        match alg {
            Slug20Algorithm::ShulginSigning => {
                let x: ShulginSignature = ShulginSignature::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::ShulginSigning(Box::new(x))))
            }
            Slug20Algorithm::AbsolveSigning => {
                let x: AbsolveSignature = AbsolveSignature::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::AbsolveSigning(Box::new(x))))
            }
            Slug20Algorithm::EsphandSigning => {
                let x: EsphandSignature = EsphandSignature::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::EsphandSigning(Box::new(x))))
            }
            Slug20Algorithm::BLS => {
                let x: BLSSignature = BLSSignature::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::BLS(x)))
            }
            Slug20Algorithm::ECDSA => {
                let x: ECDSASignature = ECDSASignature::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::ECDSA(x)))
            }
            Slug20Algorithm::Ed25519 => {
                let x: ED25519Signature = ED25519Signature::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::Ed25519(x)))
            }
            Slug20Algorithm::Ed448 => {
                let x: Ed448Signature = Ed448Signature::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::Ed448(x)))
            }
            Slug20Algorithm::Falcon => {
                let x: Falcon1024Signature = Falcon1024Signature::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::Falcon(Box::new(x))))
            }
            Slug20Algorithm::MLDSA => {
                let x: MLDSA3Signature = MLDSA3Signature::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::MLDSA(Box::new(x))))
            }
            Slug20Algorithm::Schnorr => {
                let x: SchnorrSignature = SchnorrSignature::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::Schnorr(x)))
            }
            Slug20Algorithm::SPHINCSPlus => {
                let x: SPHINCSSignature = SPHINCSSignature::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::SPHINCSPlus(Box::new(x))))
            }
        }
    }
    fn get_standard_pem_label(&self) -> String {
        match &*self.signature {
            Slug20Signature::ShulginSigning(_) => ShulginSignature::label_for_standard_pem(),
            Slug20Signature::AbsolveSigning(_) => AbsolveSignature::label_for_standard_pem(),
            Slug20Signature::EsphandSigning(_) => EsphandSignature::label_for_standard_pem(),
            Slug20Signature::BLS(_) => BLSSignature::label_for_standard_pem(),
            Slug20Signature::ECDSA(_) => ECDSASignature::label_for_standard_pem(),
            Slug20Signature::Ed25519(_) => ED25519Signature::label_for_standard_pem(),
            Slug20Signature::Ed448(_) => Ed448Signature::label_for_standard_pem(),
            Slug20Signature::Falcon(_) => Falcon1024Signature::label_for_standard_pem(),
            Slug20Signature::MLDSA(_) => MLDSA3Signature::label_for_standard_pem(),
            Slug20Signature::Schnorr(_) => SchnorrSignature::label_for_standard_pem(),
            Slug20Signature::SPHINCSPlus(_) => SPHINCSSignature::label_for_standard_pem(),
        }
    }
    fn get_standard_pem_label_with_algorithm(alg: Slug20Algorithm) -> String {
        match alg {
            Slug20Algorithm::ShulginSigning => ShulginSignature::label_for_standard_pem(),
            Slug20Algorithm::AbsolveSigning => AbsolveSignature::label_for_standard_pem(),
            Slug20Algorithm::EsphandSigning => EsphandSignature::label_for_standard_pem(),
            Slug20Algorithm::BLS => BLSSignature::label_for_standard_pem(),
            Slug20Algorithm::ECDSA => ECDSASignature::label_for_standard_pem(),
            Slug20Algorithm::Ed25519 => ED25519Signature::label_for_standard_pem(),
            Slug20Algorithm::Ed448 => Ed448Signature::label_for_standard_pem(),
            Slug20Algorithm::Falcon => Falcon1024Signature::label_for_standard_pem(),
            Slug20Algorithm::MLDSA => MLDSA3Signature::label_for_standard_pem(),
            Slug20Algorithm::Schnorr => SchnorrSignature::label_for_standard_pem(),
            Slug20Algorithm::SPHINCSPlus => SPHINCSSignature::label_for_standard_pem(),
        }
    }
}

impl OpenInternetFromPemAny for OpenInternetCryptographyAPI {
    fn from_pem<T: AsRef<str>>(pem: T) -> Result<FromPemAny, SlugErrors> {
        let x: PemEncodingSuites = PemEncodingSuites::new();
        let y: String = PemEncodingSuites::parse_pem(pem.as_ref())?;
        let alg: (Slug20Algorithm, super::__types::Slug20KeyType) = PemEncodingSuites::get_algorithm(&y);

        match alg.1 {
            Slug20KeyType::Public => {
                let public_key: OpenInternetCryptographyPublicKey = OpenInternetCryptographyPublicKey::from_standard_pem_with_algorithm(pem.as_ref(), alg.0)?;
                Ok(FromPemAny::PublicKey(public_key))
            },
            Slug20KeyType::Secret => {
                let secret_key: OpenInternetCryptographySecretKey = OpenInternetCryptographySecretKey::from_standard_pem_with_algorithm(pem.as_ref(), alg.0)?;
                Ok(FromPemAny::SecretKey(secret_key))
            },
            Slug20KeyType::Signature => {
                let signature: OpenInternetCryptographySignature = OpenInternetCryptographySignature::from_standard_pem_with_algorithm(pem.as_ref(), alg.0)?;
                Ok(FromPemAny::Signature(signature))
            },
            _ => {
                Err(SlugErrors::InvalidPemLabel)
            }
        }
    }
}

impl OpenInternetAPIGeneration for OpenInternetCryptographyKeypair {
fn generate_with_algorithm(alg: Slug20Algorithm) -> Result<OpenInternetCryptographyKeypair, SlugErrors> {
        match alg {
            Slug20Algorithm::ShulginSigning => {
                let sk: ShulginKeypair = ShulginKeypair::generate();
                let pk: ShulginKeypair = sk.into_public_key();

                let pk_output: OpenInternetCryptographyPublicKey = OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::ShulginSigning(Box::new(pk))); 
                let sk_output: OpenInternetCryptographySecretKey = OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::ShulginSigning(Box::new(sk)));

                Ok(OpenInternetCryptographyKeypair { public_key: pk_output, secret_key: sk_output })
            }
            Slug20Algorithm::AbsolveSigning => {
                let sk: AbsolveKeypair = AbsolveKeypair::generate();
                let pk: AbsolveKeypair = sk.into_public_key();

                let pk_output: OpenInternetCryptographyPublicKey = OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::AbsolveSigning(Box::new(pk))); 
                let sk_output: OpenInternetCryptographySecretKey = OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::AbsolveSigning(Box::new(sk)));

                Ok(OpenInternetCryptographyKeypair { public_key: pk_output, secret_key: sk_output })
            }
            Slug20Algorithm::EsphandSigning => {
                let sk: EsphandKeypair = EsphandKeypair::generate();
                let pk: EsphandKeypair = sk.into_public_key();

                let pk_output: OpenInternetCryptographyPublicKey = OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::EsphandSigning(Box::new(pk))); 
                let sk_output: OpenInternetCryptographySecretKey = OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::EsphandSigning(Box::new(sk)));

                Ok(OpenInternetCryptographyKeypair { public_key: pk_output, secret_key: sk_output })
            }
            Slug20Algorithm::BLS => {
                let (pk,sk) = bls::SlugBLS::generate();

                let pk_output: OpenInternetCryptographyPublicKey = OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::BLS(pk)); 
                let sk_output: OpenInternetCryptographySecretKey = OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::BLS(sk));

                Ok(OpenInternetCryptographyKeypair { public_key: pk_output, secret_key: sk_output })
            }
            Slug20Algorithm::ECDSA => {
                let sk: ECDSASecretKey = ECDSASecretKey::generate();
                let pk: ECDSAPublicKey = sk.public_key()?;

                let pk_output: OpenInternetCryptographyPublicKey = OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::ECDSA(pk)); 
                let sk_output: OpenInternetCryptographySecretKey = OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::ECDSA(sk));

                Ok(OpenInternetCryptographyKeypair { public_key: pk_output, secret_key: sk_output })
            }
            Slug20Algorithm::Ed25519 => {
                let sk: ED25519SecretKey = ED25519SecretKey::generate();
                let pk: ED25519PublicKey = sk.public_key()?;

                let pk_output: OpenInternetCryptographyPublicKey = OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::Ed25519(pk)); 
                let sk_output: OpenInternetCryptographySecretKey = OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::Ed25519(sk));

                Ok(OpenInternetCryptographyKeypair { public_key: pk_output, secret_key: sk_output })
            },
            Slug20Algorithm::Ed448 => {
                let sk: Ed448SecretKey = Ed448SecretKey::generate();
                let pk: Ed448PublicKey = sk.into_public_key();

                let pk_output: OpenInternetCryptographyPublicKey = OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::Ed448(pk)); 
                let sk_output: OpenInternetCryptographySecretKey = OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::Ed448(sk));

                Ok(OpenInternetCryptographyKeypair { public_key: pk_output, secret_key: sk_output })
            }
            Slug20Algorithm::Falcon => {
                let (pk,sk) = SlugFalcon1024::generate();

                let pk_output: OpenInternetCryptographyPublicKey = OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::Falcon(Box::new(pk))); 
                let sk_output: OpenInternetCryptographySecretKey = OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::Falcon(Box::new(sk)));

                Ok(OpenInternetCryptographyKeypair { public_key: pk_output, secret_key: sk_output })
            }
            Slug20Algorithm::MLDSA => {
                let keypair: libslug::slugcrypt::internals::signature::ml_dsa::MLDSA3Keypair  = SlugMLDSA3::generate();

                let pk = keypair.public_key();
                let sk = keypair.secret_key();

                let pk_output: OpenInternetCryptographyPublicKey = OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::MLDSA(Box::new(pk.clone()))); 
                let sk_output: OpenInternetCryptographySecretKey = OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::MLDSA(Box::new(sk.to_owned())));

                Ok(OpenInternetCryptographyKeypair { public_key: pk_output, secret_key: sk_output })
            },
            Slug20Algorithm::Schnorr => {
                let sk: SchnorrSecretKey = SchnorrSecretKey::generate();
                let pk: SchnorrPublicKey = sk.public_key().unwrap();

                let pk_output: OpenInternetCryptographyPublicKey = OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::Schnorr(pk)); 
                let sk_output: OpenInternetCryptographySecretKey = OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::Schnorr(sk));

                Ok(OpenInternetCryptographyKeypair { public_key: pk_output, secret_key: sk_output })
            },
            Slug20Algorithm::SPHINCSPlus => {
                let (pk,sk) = SPHINCSSecretKey::generate();

                let pk_output: OpenInternetCryptographyPublicKey = OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::SPHINCSPlus(pk)); 
                let sk_output: OpenInternetCryptographySecretKey = OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::SPHINCSPlus(sk));

                Ok(OpenInternetCryptographyKeypair { public_key: pk_output, secret_key: sk_output })
            }
        }
    }
}
impl OpenInternetAPIGeneration for OpenInternetCryptographyAPI {
    fn generate_with_algorithm(alg: Slug20Algorithm) -> Result<OpenInternetCryptographyKeypair, SlugErrors> {
        match alg {
            Slug20Algorithm::ShulginSigning => {
                let sk: ShulginKeypair = ShulginKeypair::generate();
                let pk = sk.into_public_key();

                let pk_output: OpenInternetCryptographyPublicKey = OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::ShulginSigning(Box::new(pk))); 
                let sk_output: OpenInternetCryptographySecretKey = OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::ShulginSigning(Box::new(sk)));

                Ok(OpenInternetCryptographyKeypair { public_key: pk_output, secret_key: sk_output })
            }
            Slug20Algorithm::AbsolveSigning => {
                let sk: AbsolveKeypair = AbsolveKeypair::generate();
                let pk = sk.into_public_key();

                let pk_output: OpenInternetCryptographyPublicKey = OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::AbsolveSigning(Box::new(pk))); 
                let sk_output: OpenInternetCryptographySecretKey = OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::AbsolveSigning(Box::new(sk)));

                Ok(OpenInternetCryptographyKeypair { public_key: pk_output, secret_key: sk_output })
            }
            Slug20Algorithm::EsphandSigning => {
                let sk: EsphandKeypair = EsphandKeypair::generate();
                let pk: EsphandKeypair = sk.into_public_key();

                let pk_output: OpenInternetCryptographyPublicKey = OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::EsphandSigning(Box::new(pk))); 
                let sk_output: OpenInternetCryptographySecretKey = OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::EsphandSigning(Box::new(sk)));

                Ok(OpenInternetCryptographyKeypair { public_key: pk_output, secret_key: sk_output })
            }
            Slug20Algorithm::BLS => {
                let (pk,sk) = bls::SlugBLS::generate();

                let pk_output: OpenInternetCryptographyPublicKey = OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::BLS(pk)); 
                let sk_output: OpenInternetCryptographySecretKey = OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::BLS(sk));

                Ok(OpenInternetCryptographyKeypair { public_key: pk_output, secret_key: sk_output })
            }
            Slug20Algorithm::ECDSA => {
                let sk: ECDSASecretKey = ECDSASecretKey::generate();
                let pk: ECDSAPublicKey = sk.public_key()?;

                let pk_output: OpenInternetCryptographyPublicKey = OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::ECDSA(pk)); 
                let sk_output: OpenInternetCryptographySecretKey = OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::ECDSA(sk));

                Ok(OpenInternetCryptographyKeypair { public_key: pk_output, secret_key: sk_output })
            }
            Slug20Algorithm::Ed25519 => {
                let sk: ED25519SecretKey = ED25519SecretKey::generate();
                let pk: ED25519PublicKey = sk.public_key()?;

                let pk_output: OpenInternetCryptographyPublicKey = OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::Ed25519(pk)); 
                let sk_output: OpenInternetCryptographySecretKey = OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::Ed25519(sk));

                Ok(OpenInternetCryptographyKeypair { public_key: pk_output, secret_key: sk_output })
            },
            Slug20Algorithm::Ed448 => {
                let sk: Ed448SecretKey = Ed448SecretKey::generate();
                let pk: Ed448PublicKey = sk.into_public_key();

                let pk_output: OpenInternetCryptographyPublicKey = OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::Ed448(pk)); 
                let sk_output: OpenInternetCryptographySecretKey = OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::Ed448(sk));

                Ok(OpenInternetCryptographyKeypair { public_key: pk_output, secret_key: sk_output })
            }
            Slug20Algorithm::Falcon => {
                let (pk,sk) = SlugFalcon1024::generate();

                let pk_output: OpenInternetCryptographyPublicKey = OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::Falcon(Box::new(pk))); 
                let sk_output: OpenInternetCryptographySecretKey = OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::Falcon(Box::new(sk)));

                Ok(OpenInternetCryptographyKeypair { public_key: pk_output, secret_key: sk_output })
            }
            Slug20Algorithm::MLDSA => {
                let keypair: libslug::slugcrypt::internals::signature::ml_dsa::MLDSA3Keypair  = SlugMLDSA3::generate();

                let pk = keypair.public_key();
                let sk = keypair.secret_key();

                let pk_output: OpenInternetCryptographyPublicKey = OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::MLDSA(Box::new(pk.clone()))); 
                let sk_output: OpenInternetCryptographySecretKey = OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::MLDSA(Box::new(sk.to_owned())));

                Ok(OpenInternetCryptographyKeypair { public_key: pk_output, secret_key: sk_output })
            },
            Slug20Algorithm::Schnorr => {
                let sk: SchnorrSecretKey = SchnorrSecretKey::generate();
                let pk: SchnorrPublicKey = sk.public_key().unwrap();

                let pk_output: OpenInternetCryptographyPublicKey = OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::Schnorr(pk)); 
                let sk_output: OpenInternetCryptographySecretKey = OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::Schnorr(sk));

                Ok(OpenInternetCryptographyKeypair { public_key: pk_output, secret_key: sk_output })
            },
            Slug20Algorithm::SPHINCSPlus => {
                let (pk,sk) = SPHINCSSecretKey::generate();

                let pk_output: OpenInternetCryptographyPublicKey = OpenInternetCryptographyPublicKey::from_slug20_public_key(Slug20PublicKey::SPHINCSPlus(pk)); 
                let sk_output: OpenInternetCryptographySecretKey = OpenInternetCryptographySecretKey::from_slug20_secret_key(Slug20SecretKey::SPHINCSPlus(sk));

                Ok(OpenInternetCryptographyKeypair { public_key: pk_output, secret_key: sk_output })
            }
        }
    }
}


/// # OpenInternetCryptographyEncryptionKey
/// 
/// This struct is a container for a public and secret key.
pub struct OpenInternetCryptographyEncryptionKey {
    pub public_key: Slug20EncryptionPublicKey,
    pub secret_key: Option<Slug20EncryptionSecretKey>,
}

pub struct OpenInternetCryptographyEncryptionCipherText {
    pub ciphertext: Vec<u8>,
}

impl OpenInternetCryptographyEncryptionKey {
    pub fn from_pk(pk: Slug20EncryptionPublicKey) -> Self {
        OpenInternetCryptographyEncryptionKey { public_key: pk, secret_key: None }
    }
    pub fn from_keys(pk: Slug20EncryptionPublicKey, sk: Slug20EncryptionSecretKey) -> Self {
        OpenInternetCryptographyEncryptionKey { public_key: pk, secret_key: Some(sk) }
    }
    pub fn encrypt<T: AsRef<[u8]>>(msg: T, pk: OpenInternetCryptographyEncryptionKey) -> Result<CipherText,SlugErrors> {
        match pk.public_key {
            Slug20EncryptionPublicKey::ECIES_ED25519(x) => {
                let output = ECIESEncrypt::encrypt(&x, msg.as_ref());

                if output.is_err() {
                    return Err(SlugErrors::Other(String::from("Error in Encryption")))
                }
                else {
                    return Ok(output.unwrap())
                }
                    
            }
        }
    }
}
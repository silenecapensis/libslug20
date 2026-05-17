//! # OpenInternetCryptographyProject Key Types
//! 
//! This module contains the core key types used in the OpenInternetCryptographyProject library.
//! 
//! ## Key Types
//! 
//! - `OpenInternetCryptographyPublicKey`: The public key type for the OpenInternetCryptographyProject library.
//! - `OpenInternetCryptographySecretKey`: The secret key type for the OpenInternetCryptographyProject library.
//! - `OpenInternetCryptographySignature`: The signature type for the OpenInternetCryptographyProject library.
//! - `OpenInternetCryptographyCipherSuite`: The cipher suite type for the OpenInternetCryptographyProject library.
//! - `OpenInternetCryptographyKeyType`: The key type type for the OpenInternetCryptographyProject library.
//! 
//! ## Usage
//! 
//! These key types are used to represent public keys, secret keys, signatures, cipher suites, and key types in the OpenInternetCryptographyProject library.
//! 
//! ## Example
//! 
//! ```rust
//! use openinternetcryptographykeys::keys::oint::usage::OpenInternetCryptographyPublicKey;
//! 
//! fn main() {
//!     let public_key: OpenInternetCryptographyPublicKey = OpenInternetCryptographyPublicKey::from_slug20_public_key(...);
//! 
//!     // ...
//! }
//! 
//! ```

use libslug::errors::SlugErrors;
use libslug::slugcrypt::internals::encryption::ecies::{ECIESEncrypt, ECPublicKey, ECSecretKey};
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize,ZeroizeOnDrop};

use libslug::slugcrypt::traits::{IntoStandardPem,FromStandardPem,FromBincode,IntoBincode};


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

use crate::prelude::essentials::{OpenInternetCryptographyPublicKey, OpenInternetCryptographySecretKey, OpenInternetCryptographySignature};

/// # PemEncodingSuites
/// 
/// This struct contains the PEM encoding suites for the OpenInternetCryptographyProject library.
/// 
/// ## Usage
/// 
/// This struct is used to represent the PEM encoding suites for the OpenInternetCryptographyProject library.
/// 
/// ## Example
/// 
/// ```rust
/// use openinternetcryptographykeys::keys::oint::usage::PemEncodingSuites;
/// 
/// fn main() {    
///     let pem_encoding_suites: PemEncodingSuites = PemEncodingSuites::new();
/// }
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct PemEncodingSuites {
    pub public_key: Vec<String>,
    pub secret_key: Vec<String>,
    pub signatures: Vec<String>,
}

/// # Slug20PublicKey
/// 
/// This enum represents the public key type for the OpenInternetCryptographyProject library.
/// 
/// ## Usage
/// 
/// This enum is used to represent the public key type for the OpenInternetCryptographyProject library.
/// 
/// ## Example
/// 
/// ```rust
/// use openinternetcryptographykeys::keys::oint::usage::Slug20PublicKey;
/// 
/// fn main() {
///     let public_key: Slug20PublicKey = Slug20PublicKey::Ed25519(...);
/// 
///     // ...
/// }
/// 
/// ```
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Hash, Zeroize, ZeroizeOnDrop)]
pub enum Slug20PublicKey {
    ShulginSigning(Box<ShulginKeypair>),
    AbsolveSigning(Box<AbsolveKeypair>),
    EsphandSigning(Box<EsphandKeypair>),
    Ed25519(ED25519PublicKey),
    Ed448(Ed448PublicKey),
    ECDSA(ECDSAPublicKey),
    Falcon(Box<Falcon1024PublicKey>),
    MLDSA(Box<MLDSA3PublicKey>),
    Schnorr(SchnorrPublicKey),
    SPHINCSPlus(SPHINCSPublicKey),
    BLS(BLSPublicKey),
}

/// # Slug20SecretKey
/// 
/// This enum represents the secret key type for the OpenInternetCryptographyProject library.
/// 
/// ## Usage
/// 
/// This enum is used to represent the secret key type for the OpenInternetCryptographyProject library.
/// 
/// ## Example
/// 
/// 
/// ```rust
/// use openinternetcryptographykeys::prelude::essentials::*;
/// use openinternetcryptographykeys::prelude::essentials::{OpenInternetAPIGeneration, OpenInternetCryptographyKeypair, OpenInternetCryptographySecretKey, OpenInternetFromPemAny, Slug20Algorithm, OpenInternetCryptographyPublicKey, OpenInternetCryptographySecretKey, OpenInternetCryptographySignature, OpenInternetFromPemAny, Slug20Algorithm};
/// 
/// 
/// fn main() {
///     let secret_key: Slug20SecretKey = Slug20SecretKey::Ed25519(ED25519SecretKey::generate());
/// }
/// 
/// ```
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Hash, Zeroize, ZeroizeOnDrop)]
pub enum Slug20SecretKey {
    ShulginSigning(Box<ShulginKeypair>),
    AbsolveSigning(Box<AbsolveKeypair>),
    EsphandSigning(Box<EsphandKeypair>),
    Ed25519(ED25519SecretKey), // derive public key
    Ed448(Ed448SecretKey), 
    ECDSA(ECDSASecretKey),
    Falcon(Box<Falcon1024SecretKey>),
    MLDSA(Box<MLDSA3SecretKey>),
    Schnorr(SchnorrSecretKey),
    SPHINCSPlus(SPHINCSSecretKey),
    BLS(BLSSecretKey),
}

/// # Slug20Signature
/// 
/// This enum represents the signature type for the OpenInternetCryptographyProject library.
/// 
/// ## Usage
/// 
/// This enum is used to represent the signature type for the OpenInternetCryptographyProject library.
/// 
/// ## Example
/// 
/// ```rust
/// 
/// use openinternetcryptographykeys::keys::oint::usage::Slug20Signature;
/// 
/// fn main() {
///     let signature: Slug20Signature = Slug20Signature::Ed25519(...);
/// 
///     // ...
/// }
/// 
/// ```
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Hash, Zeroize, ZeroizeOnDrop)]
pub enum Slug20Signature {
    ShulginSigning(Box<ShulginSignature>),
    AbsolveSigning(Box<AbsolveSignature>),
    EsphandSigning(Box<EsphandSignature>),
    Ed25519(ED25519Signature),
    Ed448(Ed448Signature),
    ECDSA(ECDSASignature),
    Falcon(Box<Falcon1024Signature>),
    MLDSA(Box<MLDSA3Signature>),
    Schnorr(SchnorrSignature),
    SPHINCSPlus(Box<SPHINCSSignature>),
    BLS(BLSSignature),
}

pub enum Slug20EncryptionPublicKey {
    ECIES_ED25519(ECPublicKey),
}

pub enum Slug20EncryptionSecretKey {
    ECIES_ED25519(ECSecretKey),
}

/// # Key Type
/// 
/// This enum represents the key type for the OpenInternetCryptographyProject library.
/// 
/// ## Usage
/// 
/// This enum is used to represent the key type for the OpenInternetCryptographyProject library.
/// 
/// ## Example
/// 
/// ```rust
/// 
/// use openinternetcryptographykeys::keys::oint::usage::Slug20KeyType;
/// 
/// fn main() {
///     let key_type: Slug20KeyType = Slug20KeyType::Public;
/// 
///     // ...
/// }
/// 
/// ```
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Hash, Zeroize, ZeroizeOnDrop)]
pub enum Slug20KeyType {
    Public,
    Secret,
    Signature,
    Keypair,
}

/// # FromPemAny
/// 
/// This enum lets you decode from any PEM-encoded types and retrieve the correct type.
/// 
/// ## Usage
/// 
/// This enum is used to let you decode from any PEM-encoded types and retrieve the correct type.
/// 
/// ## Example
/// 
/// ```rust
/// 
/// use openinternetcryptographykeys::keys::oint::usage::FromPemAny;
/// 
/// fn main() {
///     let from_pem_any: FromPemAny = FromPemAny::PublicKey(...);
/// 
///     // ...
/// }
/// 
/// ```
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Hash, Zeroize, ZeroizeOnDrop)]
pub enum FromPemAny {
    PublicKey(OpenInternetCryptographyPublicKey),
    SecretKey(OpenInternetCryptographySecretKey),
    Signature(OpenInternetCryptographySignature),
}


/// # Slug20Algorithm
/// 
/// This enum represents the algorithm type for the OpenInternetCryptographyProject library.
/// 
/// ## Usage
/// 
/// This enum is used to represent the algorithm type for the OpenInternetCryptographyProject library.
/// 
/// ## Example
/// 
/// ```rust
/// 
/// use openinternetcryptographykeys::keys::oint::usage::Slug20Algorithm;
/// 
/// fn main() {
///     let algorithm: Slug20Algorithm = Slug20Algorithm::Ed25519;
/// 
///     // ...
/// }
/// 
/// ```
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Hash, Zeroize, ZeroizeOnDrop)]
pub enum Slug20Algorithm {
    ShulginSigning,
    AbsolveSigning,
    EsphandSigning,
    Ed25519,
    Ed448,
    ECDSA,
    Falcon,
    MLDSA,
    Schnorr,
    SPHINCSPlus,
    BLS,
}

impl Slug20Algorithm {
    pub fn get_pem_label(alg: Slug20Algorithm, key_type: Slug20KeyType) -> String {
        match key_type {
            Slug20KeyType::Public => {
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
                }
            },
            Slug20KeyType::Secret => {
                match alg {
                    Slug20Algorithm::ShulginSigning => ShulginKeypair::label_for_standard_pem_secret(),
                    Slug20Algorithm::AbsolveSigning => AbsolveKeypair::label_for_standard_pem_secret(),
                    Slug20Algorithm::EsphandSigning => EsphandKeypair::label_for_standard_pem_secret(),
                    Slug20Algorithm::BLS => BLSSecretKey::label_for_standard_pem_secret(),
                    Slug20Algorithm::ECDSA => ECDSASecretKey::label_for_standard_pem_secret(),
                    Slug20Algorithm::Ed25519 => ED25519SecretKey::label_for_standard_pem_secret(),
                    Slug20Algorithm::Ed448 => Ed448SecretKey::label_for_standard_pem_secret(),
                    Slug20Algorithm::Falcon => Falcon1024SecretKey::label_for_standard_pem_secret(),
                    Slug20Algorithm::MLDSA => MLDSA3SecretKey::label_for_standard_pem_secret(),
                    Slug20Algorithm::Schnorr => SchnorrSecretKey::label_for_standard_pem_secret(),
                    Slug20Algorithm::SPHINCSPlus => SPHINCSSecretKey::label_for_standard_pem_secret(),
                }
            },
            Slug20KeyType::Signature => {
                match alg {
                    Slug20Algorithm::ShulginSigning => ShulginSignature::label_for_standard_pem(),
                    Slug20Algorithm::AbsolveSigning => AbsolveSignature::label_for_standard_pem(),
                    Slug20Algorithm::EsphandSigning => EsphandSignature::label_for_standard_pem(),
                    Slug20Algorithm::Ed25519 => ED25519Signature::label_for_standard_pem(),
                    Slug20Algorithm::Ed448 => Ed448Signature::label_for_standard_pem(),
                    Slug20Algorithm::ECDSA => ECDSASignature::label_for_standard_pem(),
                    Slug20Algorithm::Falcon => Falcon1024Signature::label_for_standard_pem(),
                    Slug20Algorithm::MLDSA => MLDSA3Signature::label_for_standard_pem(),
                    Slug20Algorithm::Schnorr => SchnorrSignature::label_for_standard_pem(),
                    Slug20Algorithm::SPHINCSPlus => SPHINCSSignature::label_for_standard_pem(),
                    Slug20Algorithm::BLS => BLSSignature::label_for_standard_pem(),
                }
            },
            //TODO: Edit this
            Slug20KeyType::Keypair => {
                match alg {
                    Slug20Algorithm::ShulginSigning => ShulginKeypair::label_for_standard_pem(),
                    Slug20Algorithm::AbsolveSigning => AbsolveKeypair::label_for_standard_pem(),
                    Slug20Algorithm::EsphandSigning => EsphandKeypair::label_for_standard_pem(),
                    Slug20Algorithm::BLS => BLSSecretKey::label_for_standard_pem(),
                    Slug20Algorithm::ECDSA => ECDSASecretKey::label_for_standard_pem(),
                    Slug20Algorithm::Ed25519 => ED25519SecretKey::label_for_standard_pem(),
                    Slug20Algorithm::Ed448 => Ed448SecretKey::label_for_standard_pem(),
                    Slug20Algorithm::Falcon => Falcon1024SecretKey::label_for_standard_pem(),
                    Slug20Algorithm::MLDSA => MLDSA3SecretKey::label_for_standard_pem(),
                    Slug20Algorithm::Schnorr => SchnorrSecretKey::label_for_standard_pem(),
                    Slug20Algorithm::SPHINCSPlus => SPHINCSSecretKey::label_for_standard_pem(),
                }
            }
        }
    }
    pub fn get_pem_label_keypair(alg: Slug20Algorithm) -> String {
        match alg {
            Slug20Algorithm::ShulginSigning => ShulginKeypair::label_for_standard_pem(),
            Slug20Algorithm::AbsolveSigning => AbsolveKeypair::label_for_standard_pem(),
            Slug20Algorithm::EsphandSigning => EsphandKeypair::label_for_standard_pem(),
            Slug20Algorithm::BLS => BLSSecretKey::label_for_standard_pem(),
            Slug20Algorithm::ECDSA => ECDSASecretKey::label_for_standard_pem(),
            Slug20Algorithm::Ed25519 => ED25519SecretKey::label_for_standard_pem(),
            Slug20Algorithm::Ed448 => Ed448SecretKey::label_for_standard_pem(),
            Slug20Algorithm::Falcon => Falcon1024SecretKey::label_for_standard_pem(),
            Slug20Algorithm::MLDSA => MLDSA3SecretKey::label_for_standard_pem(),
            Slug20Algorithm::Schnorr => SchnorrSecretKey::label_for_standard_pem(),
            Slug20Algorithm::SPHINCSPlus => SPHINCSSecretKey::label_for_standard_pem(),
        }
    }
    pub fn get_pem_label_secret(alg: Slug20Algorithm) -> String {
        match alg {
            Slug20Algorithm::ShulginSigning => ShulginKeypair::label_for_standard_pem_secret(),
            Slug20Algorithm::AbsolveSigning => AbsolveKeypair::label_for_standard_pem_secret(),
            Slug20Algorithm::EsphandSigning => EsphandKeypair::label_for_standard_pem_secret(),
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
    pub fn get_pem_label_public(alg: Slug20Algorithm) -> String {
        match alg {
            Slug20Algorithm::ShulginSigning => ShulginKeypair::label_for_standard_pem(),
            Slug20Algorithm::AbsolveSigning => AbsolveKeypair::label_for_standard_pem(),
            Slug20Algorithm::EsphandSigning => EsphandKeypair::label_for_standard_pem(),
            Slug20Algorithm::Ed25519 => ED25519SecretKey::label_for_standard_pem(),
            Slug20Algorithm::Ed448 => Ed448SecretKey::label_for_standard_pem(),
            Slug20Algorithm::ECDSA => ECDSASecretKey::label_for_standard_pem(),
            Slug20Algorithm::Falcon => Falcon1024SecretKey::label_for_standard_pem(),
            Slug20Algorithm::MLDSA => MLDSA3SecretKey::label_for_standard_pem(),
            Slug20Algorithm::Schnorr => SchnorrSecretKey::label_for_standard_pem(),
            Slug20Algorithm::SPHINCSPlus => SPHINCSSecretKey::label_for_standard_pem(),
            Slug20Algorithm::BLS => BLSSecretKey::label_for_standard_pem(),
        }
    }
    pub fn get_pem_label_signature(alg: Slug20Algorithm) -> String {
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
    pub fn enumerate_pem_labels() -> Vec<Vec<String>> {
        let public_keys_pem_labels = {
            vec![
                ShulginKeypair::label_for_standard_pem(),
                AbsolveKeypair::label_for_standard_pem(),
                EsphandKeypair::label_for_standard_pem(),
                ED25519PublicKey::label_for_standard_pem(),
                Ed448PublicKey::label_for_standard_pem(),
                ECDSAPublicKey::label_for_standard_pem(),
                Falcon1024PublicKey::label_for_standard_pem(),
                MLDSA3PublicKey::label_for_standard_pem(),
                SchnorrPublicKey::label_for_standard_pem(),
                SPHINCSPublicKey::label_for_standard_pem(),
                BLSPublicKey::label_for_standard_pem(),
            ]
        };
        let secret_keys_pem_labels = {
            vec![
                ShulginKeypair::label_for_standard_pem_secret(),
                AbsolveKeypair::label_for_standard_pem_secret(),
                EsphandKeypair::label_for_standard_pem_secret(),
                ED25519SecretKey::label_for_standard_pem_secret(),
                Ed448SecretKey::label_for_standard_pem_secret(),
                ECDSASecretKey::label_for_standard_pem_secret(),
                Falcon1024SecretKey::label_for_standard_pem_secret(),
                MLDSA3SecretKey::label_for_standard_pem_secret(),
                SchnorrSecretKey::label_for_standard_pem_secret(),
                SPHINCSSecretKey::label_for_standard_pem_secret(),
                BLSSecretKey::label_for_standard_pem_secret(),
            ]
        };
        let signature_pem_labels = {
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
        };
        vec![public_keys_pem_labels, secret_keys_pem_labels, signature_pem_labels]
    }
    pub fn enumerate_into_object() -> PemEncodingSuites {
        let x: Vec<Vec<String>> =Self::enumerate_pem_labels();

        return PemEncodingSuites { public_key: x[0].clone(), secret_key: x[1].clone(), signatures: x[2].clone() }
    }
}

impl PemEncodingSuites {
    pub fn new() -> PemEncodingSuites {
        let x: PemEncodingSuites = Slug20Algorithm::enumerate_into_object();
        return x
    }
    pub fn compare<T: AsRef<str>>(label: T) -> Slug20Algorithm {
        let x: PemEncodingSuites = Slug20Algorithm::enumerate_into_object();
        for i in x.public_key.iter() {
            if i == label.as_ref() {
                return Slug20Algorithm::ShulginSigning
            }
        }
        for i in x.secret_key.iter() {
            if i == label.as_ref() {
                return Slug20Algorithm::ShulginSigning
            }
        }
        for i in x.signatures.iter() {
            if i == label.as_ref() {
                return Slug20Algorithm::ShulginSigning
            }
        }
        panic!("PemEncodingSuites::compare: label not found")
    }
    pub fn enumerate() {
        let x: PemEncodingSuites = Slug20Algorithm::enumerate_into_object();
        for i in x.public_key.iter() {
            println!("{}", i);
        }
        for i in x.secret_key.iter() {
            println!("{}", i);
        }
        for i in x.signatures.iter() {
            println!("{}", i);
        }
    }
    pub fn get_algorithm(label: &str) -> (Slug20Algorithm,Slug20KeyType) {
        let x: PemEncodingSuites = Self::new();

        match label {
            //=====PUBLIC KEYS=====//
            "OpenInternetCryptographyProject/ShulginSigning-Public-Key" => (Slug20Algorithm::ShulginSigning,Slug20KeyType::Public),
            "OpenInternetCryptographyProject/AbsolveSigning-Public-Key" => (Slug20Algorithm::AbsolveSigning,Slug20KeyType::Public),
            "OpenInternetCryptographyProject/EsphandSignature-Public-Key" => (Slug20Algorithm::EsphandSigning,Slug20KeyType::Public),
            "OpenInternetCryptographyProject/ED25519-Public-Key" => (Slug20Algorithm::Ed25519,Slug20KeyType::Public),
            "OpenInternetCryptographyProject/ED448-PUBLIC-KEY" => (Slug20Algorithm::Ed448,Slug20KeyType::Public),
            "OpenInternetCryptographyProject/ECDSA-SECP256K1-Public-Key" => (Slug20Algorithm::ECDSA,Slug20KeyType::Public),
            "OpenInternetCryptographyProject/FALCON1024-PUBLIC-KEY" => (Slug20Algorithm::Falcon,Slug20KeyType::Public),
            "OpenInternetCryptographyProject/MLDSA3-PUBLIC-KEY" => (Slug20Algorithm::MLDSA,Slug20KeyType::Public),
            "OpenInternetCryptographyProject/SCHNORR-PUBLIC-KEY" => (Slug20Algorithm::Schnorr,Slug20KeyType::Public),
            "OpenInternetCryptographyProject/SPHINCS+ PUBLIC KEY" => (Slug20Algorithm::SPHINCSPlus,Slug20KeyType::Public),
            "OpenInternetCryptographyProject/BLS12-381-Public-Key" => (Slug20Algorithm::BLS,Slug20KeyType::Public),

            //=====SECRET KEYS=====//
            "OpenInternetCryptographyProject/ED25519-Secret-Key" => (Slug20Algorithm::Ed25519,Slug20KeyType::Secret),
            "OpenInternetCryptographyProject/ED448-SECRET-KEY" => (Slug20Algorithm::Ed448,Slug20KeyType::Secret),
            "OpenInternetCryptographyProject/ECDSA-SECP256K1-Secret-Key" => (Slug20Algorithm::ECDSA,Slug20KeyType::Secret),
            "OpenInternetCryptographyProject/FALCON1024-SECRET-KEY" => (Slug20Algorithm::Falcon,Slug20KeyType::Secret),
            "OpenInternetCryptographyProject/MLDSA3-SECRET-KEY" => (Slug20Algorithm::MLDSA,Slug20KeyType::Secret),
            "OpenInternetCryptographyProject/SCHNORR-SECRET-KEY" => (Slug20Algorithm::Schnorr,Slug20KeyType::Secret),
            "OpenInternetCryptographyProject/SPHINCS+ SECRET KEY" => (Slug20Algorithm::SPHINCSPlus,Slug20KeyType::Secret),
            "OpenInternetCryptographyProject/BLS12-381-Secret-Key" => (Slug20Algorithm::BLS,Slug20KeyType::Secret),
            "OpenInternetCryptographyProject/ShulginSigning-Secret-Key" => (Slug20Algorithm::ShulginSigning,Slug20KeyType::Secret),
            "OpenInternetCryptographyProject/AbsolveSigning-Secret-Key" => (Slug20Algorithm::AbsolveSigning,Slug20KeyType::Secret),
            "OpenInternetCryptographyProject/EsphandSignature-Secret-Key" => (Slug20Algorithm::EsphandSigning,Slug20KeyType::Secret),

            //=====SIGNATURES=====//
            "OpenInternetCryptographyProject/SPHINCS+ SIGNATURE" => (Slug20Algorithm::SPHINCSPlus,Slug20KeyType::Signature),
            "OpenInternetCryptographyProject/ED25519-Signature" => (Slug20Algorithm::Ed25519,Slug20KeyType::Signature),
            "OpenInternetCryptographyProject/ED448-Signature" => (Slug20Algorithm::Ed448,Slug20KeyType::Signature),
            "OpenInternetCryptographyProject/ED448-SIGNATURE" => (Slug20Algorithm::Ed448,Slug20KeyType::Signature),
            "OpenInternetCryptographyProject/ECDSA-SECP256K1-Signature" => (Slug20Algorithm::ECDSA,Slug20KeyType::Signature),
            "OpenInternetCryptographyProject/FALCON1024-Signature" => (Slug20Algorithm::Falcon,Slug20KeyType::Signature),
            "OpenInternetCryptographyProject/FALCON1024-SIGNATURE" => (Slug20Algorithm::Falcon,Slug20KeyType::Signature),
            "OpenInternetCryptographyProject/MLDSA3-Signature" => (Slug20Algorithm::MLDSA,Slug20KeyType::Signature),
            "OpenInternetCryptographyProject/MLDSA3-SIGNATURE" => (Slug20Algorithm::MLDSA,Slug20KeyType::Signature),
            "OpenInternetCryptographyProject/SCHNORR-Signature" => (Slug20Algorithm::Schnorr,Slug20KeyType::Signature),
            "OpenInternetCryptographyProject/BLS12-381-Signature" => (Slug20Algorithm::BLS,Slug20KeyType::Signature),
            "OpenInternetCryptographyProject/ShulginSigning-Signature" => (Slug20Algorithm::ShulginSigning,Slug20KeyType::Signature),
            "OpenInternetCryptographyProject/AbsolveSigning-Signature" => (Slug20Algorithm::AbsolveSigning,Slug20KeyType::Signature),
            "OpenInternetCryptographyProject/EsphandSignature-Signature" => (Slug20Algorithm::EsphandSigning,Slug20KeyType::Signature),

            _ => {
                return (Slug20Algorithm::Schnorr,Slug20KeyType::Signature)
            }
        }
    }
    pub fn enumerate_pem_labels(&self) {
        
    }
    pub fn parse_pem<T: AsRef<str>>(label: T) -> Result<String,SlugErrors> {
        let pem: String = label.as_ref().to_string();

        let x: PemEncodingSuites = PemEncodingSuites::new();


        for i in x.public_key.iter() {
            if pem.contains(i.as_str()) {
                return Ok(i.to_owned())
            }
        }
        for i in x.secret_key.iter() {
            if pem.contains(i.as_str()) {
                return Ok(i.to_owned())
            }
        }
        for i in x.signatures.iter() {
            if pem.contains(i.as_str()) {
                return Ok(i.to_owned())
            }
        }

        return Err(SlugErrors::InvalidPemLabel)
    }
}

impl Slug20SecretKey {
    pub fn as_pem_label_secret(&self) -> String {
        match self {
            Slug20SecretKey::ShulginSigning(_) => ShulginKeypair::label_for_standard_pem_secret(),
            Slug20SecretKey::AbsolveSigning(_) => AbsolveKeypair::label_for_standard_pem_secret(),
            Slug20SecretKey::EsphandSigning(_) => EsphandKeypair::label_for_standard_pem_secret(),
            Slug20SecretKey::Ed25519(_) => ED25519SecretKey::label_for_standard_pem_secret(),
            Slug20SecretKey::Ed448(_) => Ed448SecretKey::label_for_standard_pem_secret(),
            Slug20SecretKey::ECDSA(_) => ECDSASecretKey::label_for_standard_pem_secret(),
            Slug20SecretKey::Falcon(_) => Falcon1024SecretKey::label_for_standard_pem_secret(),
            Slug20SecretKey::MLDSA(_) => MLDSA3SecretKey::label_for_standard_pem_secret(),
            Slug20SecretKey::Schnorr(_) => SchnorrSecretKey::label_for_standard_pem_secret(),
            Slug20SecretKey::SPHINCSPlus(_) => SPHINCSSecretKey::label_for_standard_pem_secret(),
            Slug20SecretKey::BLS(_) => BLSSecretKey::label_for_standard_pem_secret(),
        }
    }
    pub fn get_pem_label_secret(alg: Slug20Algorithm) -> String {
        match alg {
            Slug20Algorithm::ShulginSigning => ShulginKeypair::label_for_standard_pem_secret(),
            Slug20Algorithm::AbsolveSigning => AbsolveKeypair::label_for_standard_pem_secret(),
            Slug20Algorithm::EsphandSigning => EsphandKeypair::label_for_standard_pem_secret(),
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
}
impl Slug20PublicKey {
    pub fn as_pem_label_public(&self) -> String {
        match self {
            Slug20PublicKey::ShulginSigning(_) => ShulginKeypair::label_for_standard_pem(),
            Slug20PublicKey::AbsolveSigning(_) => AbsolveKeypair::label_for_standard_pem(),
            Slug20PublicKey::EsphandSigning(_) => EsphandKeypair::label_for_standard_pem(),
            Slug20PublicKey::Ed25519(_) => ED25519PublicKey::label_for_standard_pem(),
            Slug20PublicKey::Ed448(_) => Ed448PublicKey::label_for_standard_pem(),
            Slug20PublicKey::ECDSA(_) => ECDSAPublicKey::label_for_standard_pem(),
            Slug20PublicKey::Falcon(_) => Falcon1024PublicKey::label_for_standard_pem(),
            Slug20PublicKey::MLDSA(_) => MLDSA3PublicKey::label_for_standard_pem(),
            Slug20PublicKey::Schnorr(_) => SchnorrPublicKey::label_for_standard_pem(),
            Slug20PublicKey::SPHINCSPlus(_) => SPHINCSPublicKey::label_for_standard_pem(),
            Slug20PublicKey::BLS(_) => BLSPublicKey::label_for_standard_pem(),
        }
    }
    pub fn get_pem_label_public(alg: Slug20Algorithm) -> String {
        match alg {
            Slug20Algorithm::ShulginSigning => ShulginKeypair::label_for_standard_pem(),
            Slug20Algorithm::AbsolveSigning => AbsolveKeypair::label_for_standard_pem(),
            Slug20Algorithm::EsphandSigning => EsphandKeypair::label_for_standard_pem(),
            Slug20Algorithm::Ed25519 => ED25519PublicKey::label_for_standard_pem(),
            Slug20Algorithm::Ed448 => Ed448PublicKey::label_for_standard_pem(),
            Slug20Algorithm::ECDSA => ECDSAPublicKey::label_for_standard_pem(),
            Slug20Algorithm::Falcon => Falcon1024PublicKey::label_for_standard_pem(),
            Slug20Algorithm::MLDSA => MLDSA3PublicKey::label_for_standard_pem(),
            Slug20Algorithm::Schnorr => SchnorrPublicKey::label_for_standard_pem(),
            Slug20Algorithm::SPHINCSPlus => SPHINCSPublicKey::label_for_standard_pem(),
            Slug20Algorithm::BLS => BLSPublicKey::label_for_standard_pem(),
        }
    }
}

impl Slug20Signature {
    pub fn as_pem_label_signature(&self) -> String {
        match self {
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
    pub fn get_pem_label_signature(alg: Slug20Algorithm) -> String {
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

#[test]
fn run() {
    PemEncodingSuites::enumerate();
}
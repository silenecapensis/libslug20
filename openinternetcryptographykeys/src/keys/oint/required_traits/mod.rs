//! # Required Traits for Open Internet Cryptography Keys (OICK)
//! 
//! ## Description
//! 
//! This module contains the required traits to be implemented for OpenInternetCryptographyKeys (OICK) key types, ensuring that they adhere to the necessary functionality for signing, verifying, key derivation, and generation as defined by the OICK specification.
//! 
//! ## Traits
//! 
//! ### Core
//! 
//! - [X] `OpenInternetSigner`: Trait for signing messages with a context to produce a signature.
//! - [X] `OpenInternetVerifier`: Trait for verifying signatures against messages and contexts.
//! - [X] `OpenInternetPublicKeyDerive`: Trait for deriving a public key from a secret key.
//! - [X] `OpenInternetGeneration`: Trait for generating keys based on a provided string input.
//! - [X] `OpenInternetAPIGeneration`: Trait for generating keys based on a provided API input.
//! 
//! ### Encoding
//! 
//! - [X] `OpenInternetIntoStandardPEM`: Trait for converting a key to a standard PEM format.
//! - [X] `OpenInternetFromStandardPEM`: Trait for converting a standard PEM format to a key type.
//! - [X] `OpenInternetFromPemAny`: Trait for converting a standard PEM format to a key type.
//! 
//! ## Usage
//! 
//! These traits are used to implement the Open Internet Cryptography Keys (OICK) library, allowing for signing, verifying, key derivation, and generation of keys.

use fixedstr::str192;
use libslug::errors::SlugErrors;

use crate::{keys::oint::{__types::{FromPemAny, Slug20Algorithm}, usage::{OpenInternetCryptographyPublicKey, OpenInternetCryptographySignature}}, prelude::essentials::{OpenInternetCryptographyKeypair, OpenInternetCryptographySecretKey}};

//=====OPENINTERNETCRYPTOGRAPHYKEYS OINT REQUIRED TRAITS=====

/// # OpenInternetCryptographyTraits Trait
/// 
/// This trait is a composite of all the required traits for Open Internet Cryptography Keys (OICK) key types, ensuring that any type implementing this trait adheres to the necessary functionality for signing, verifying, key derivation, and generation as defined by the OICK specification.
pub trait OpenInternetCryptographyTraits: OpenInternetSigner + OpenInternetVerifier + OpenInternetPublicKeyDerive + OpenInternetGeneration + OpenInternetIntoStandardPEM + OpenInternetFromStandardPEM + OpenInternetFromPemAny {}

/// # OpenInternetSigner Trait
/// 
/// This trait implements signing functionality for the Open Internet Cryptography Keys (OICK) library, allowing for signing messages with a context to produce a signature.
pub trait OpenInternetSigner: Sized {
    /// # Sign With Context
    /// 
    /// Allows Signing of Data as Bytes with a Context.
    fn sign_with_context<T: AsRef<[u8]>>(&self, message: T, context: T) -> Result<OpenInternetCryptographySignature, SlugErrors>;
    /// # Sign
    /// 
    /// Allows Signing of Data as Bytes. Defaults to `OpenInternetCryptographyStandardContext`
    fn sign<T: AsRef<[u8]>>(&self, message: T) -> Result<OpenInternetCryptographySignature, SlugErrors> {
        self.sign_with_context(message.as_ref(), "OpenInternetCryptographyStandardContext".as_bytes())
    }
}

/// # OpenInternetVerifier Trait
/// 
/// This trait implements verification functionality for the Open Internet Cryptography Keys (OICK) library, allowing for verifying signatures against messages and contexts.
pub trait OpenInternetVerifier: Sized {
    fn verify_with_context<T: AsRef<[u8]>>(&self, message: T, context: T, signature: &OpenInternetCryptographySignature) -> Result<bool, SlugErrors>;
    fn verify<T: AsRef<[u8]>>(&self, message: T, signature: &OpenInternetCryptographySignature) -> Result<bool, SlugErrors> {
        self.verify_with_context(message.as_ref(), "OpenInternetCryptographyStandardContext".as_bytes(), signature)
    }
}

/// # OpenInternetPublicKeyDerive Trait
/// 
/// This trait implements key derivation functionality for the Open Internet Cryptography Keys (OICK) library, allowing for deriving a public key from a secret key.
pub trait OpenInternetPublicKeyDerive: Sized {
    fn derive_public_key(&self) -> Result<OpenInternetCryptographyPublicKey, SlugErrors>;
}

/// # OpenInternetGeneration Trait
/// 
/// This trait implements key generation functionality for the Open Internet Cryptography Keys (OICK) library, allowing for generating keys based on a provided string input.
pub trait OpenInternetGeneration: Sized {
    fn generate_with_algorithm(alg: Slug20Algorithm) -> Result<Self, SlugErrors>;
}

//=====OPENINTERNETCRYPTOGRAPHYKEYS OINT REQUIRED TRAITS END=====
/// # OpenInternetIntoStandardPEM Trait
/// 
/// This trait implements conversion to a standard PEM format for the Open Internet Cryptography Keys (OICK) library.
pub trait OpenInternetIntoStandardPEM {
    fn into_standard_pem(&self) -> Result<String, SlugErrors>;
    fn as_standard_pem_label(&self) -> String;
}

/// # OpenInternetFromStandardPEM Trait
/// 
/// This trait implements conversion from a standard PEM format for the Open Internet Cryptography Keys (OICK) library.
pub trait OpenInternetFromStandardPEM: Sized {
    /// # From Standard PEM (With Algorithm)
    /// 
    /// Converts a standard PEM format into the type implementing this trait using bincode as the underlying deserialization format.
    fn from_standard_pem_with_algorithm<T: AsRef<str>>(pem: T, alg: Slug20Algorithm) -> Result<Self, SlugErrors>;
    /// # From Standard PEM
    /// 
    /// Converts a standard PEM format into the type implementing this trait using bincode as the underlying deserialization format.
    //fn from_standard_pem<T: AsRef<str>>(pem: T) -> Result<Self, SlugErrors>;
    
    // PEM Label
    fn get_standard_pem_label(&self) -> String;
    fn get_standard_pem_label_with_algorithm(alg: Slug20Algorithm) -> String;
    fn enumerate_standard_pem_labels() -> Vec<String>;
}

/// # OpenInternetFromPemAny Trait
/// 
/// This trait implements conversion from a standard PEM format for the Open Internet Cryptography Keys (OICK) library.
pub trait OpenInternetFromPemAny: Sized {
    fn from_pem<T: AsRef<str>>(pem: T) -> Result<FromPemAny, SlugErrors>;
}

/// # OpenInternetAPIGeneration Trait
/// 
/// This trait implements key generation functionality for the Open Internet Cryptography Keys (OICK) library, allowing for generating keys based on a provided string input.
pub trait OpenInternetAPIGeneration: Sized {
    fn generate_with_algorithm(alg: Slug20Algorithm) -> Result<OpenInternetCryptographyKeypair, SlugErrors>;
}
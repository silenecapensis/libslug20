//! # SLH-DSA (SHAKE256s) (Level 5)
//! 
//! Also known as SPHINCS+, this is the standardized implementation of SLH-DSA5.
//! 
//! ## Generation
//! 
//! - [X] Generate Using ThreadRNG
//! - [ ] Generate Using Operating System Randomness
//! - [X] Generate Using BIP39 With Options
//!     - [X] Generate Using BIP39 With Password To Derive Seed
//!     - [X] Generate Using BIP39 Without Password To Derive Seed
//! 
//! ## Signing
//! 
//! - [ ] Deterministic Signing
//! - [ ] Randomized Signing
//! 
//! ## TODO
//! 
//! - [ ] Add Support For Sensitive Bytes
//! - [ ] Signing
//! - [ ] Encoding
//! 
//! ## TODO: Traits
//! 
//! - [X] Bincode
//!     - [X] From
//!     - [X] Into
//! - [X] Encoding
//!     - [X] From
//!     - [X] Into
//! - [X] StandardPEM
//!     - [X] From
//!     - [X] Into

use std::str::FromStr;

use base58::FromBase58;
use digest::typenum::U64;
use digest::typenum::U128;
use pem::Pem;
use securerand_rs::bip39::*;
use serde::{Serialize,Deserialize};
use slh_dsa::SigningKey;
use slugencode::SlugEncodings;
use zeroize::{Zeroize,ZeroizeOnDrop};
use serde_big_array::BigArray;
use slh_dsa::Shake256s;
use slh_dsa::*;
use slh_dsa::VerifyingKey;
use slh_dsa::ParameterSet;
use slh_dsa::signature::Keypair;
use slh_dsa::signature::RandomizedSigner;
use slh_dsa::signature::Signer;
use slh_dsa::VerifyingKeyLen;
use slh_dsa::SigningKeyLen;
use slh_dsa::signature::Verifier;
use slh_dsa::signature::SignatureEncoding;
use slh_dsa::signature::KeypairRef;
use slh_dsa::signature::RandomizedSignerMut;
use rand::rngs::OsRng;
use fixedstr::str192;

use slugencode::SlugEncodingUsage;

use hybird_array_four::{Array,ArraySize,ArrayN,AssocArraySize};

use crate::errors::SlugErrors;
use crate::slugcrypt::traits::FromBincode;
use crate::slugcrypt::traits::FromEncoding;
use crate::slugcrypt::traits::FromStandardPem;
use crate::slugcrypt::traits::IntoBincode;
use crate::slugcrypt::traits::IntoEncoding;
use crate::slugcrypt::traits::IntoStandardPem;

pub mod info {
    pub const CIPHER_SUITE: &str = "OpenInternetCryptographyProject/Standardized/SLH-DSA5";
    pub const PROTOCOL_NAME: &str = "libslug20/slh_dsa_shake256_level_5";
    pub const PUBLIC_KEY_SIZE: usize = 64;
    pub const SECRET_KEY_SIZE: usize = 128;
    pub const SIGNATURE_SIZE: usize = 29_792;
}

/// # SLH-DSA5 Public Key
/// 
/// SLH-DSA5 Public Key structure, containing the raw public key bytes. The public key is 64 bytes in size, and is generated using the SLH-DSA algorithm with SHAKE256s as the underlying hash function.
#[derive(Debug, Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop, PartialEq, PartialOrd, Hash)]
pub struct SLHDSA5PublicKey {
    #[serde(with = "BigArray")]
    pub pk: [u8; 64]
}

/// # SLH-DSA5 Secret Key
/// 
/// SLH-DSA5 Secret Key structure, containing the raw secret key bytes. The secret key is 128 bytes in size, and is generated using the SLH-DSA algorithm with SHAKE256s as the underlying hash function.
#[derive(Debug, Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop, PartialEq, PartialOrd, Hash)]
pub struct SLHDSA5SecretKey {
    #[serde(with = "BigArray")]
    pub sk: [u8; 128]
}


/// # SLH-DSA5 Signature
/// 
/// SLH-DSA5 Signature structure, containing the raw signature bytes. The signature is 29,792 bytes in size, and is generated using the SLH-DSA algorithm with SHAKE256s as the underlying hash function.
#[derive(Debug, Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop, PartialEq, PartialOrd, Hash)]
pub struct SLHDSA5Signature {
    #[serde(with = "BigArray")]
    pub sig: [u8; 29_792]
}

/// # SLH-DSA5 Signature CID
/// 
/// Content Identifier for SLH-DSA5 signatures, used for referencing signatures without revealing the signature itself.
#[derive(Debug, Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop, PartialEq, PartialOrd, Hash)]
pub struct SLHDSA5SignatureCID {
    #[serde(with = "BigArray")]
    pub cid: [u8; 64],
}

pub struct GenerateSLHDSA5;

impl GenerateSLHDSA5 {
    /// Generate a new SLH-DSA5 secret key using the thread RNG. This method is suitable for general use cases where high-quality randomness is required.
    pub fn generate() -> SLHDSA5SecretKey {
        SLHDSA5SecretKey::generate_using_threadrng()
    }
    /// Generate a new SLH-DSA5 secret key using BIP39 mnemonic and password. This method allows for deterministic key generation based on a mnemonic phrase and an optional password, making it suitable for backup and recovery scenarios.
    pub fn generate_with_bip39(mnemonic: SlugMnemonic, password: &str) -> SLHDSA5SecretKey {
        SLHDSA5SecretKey::generate_with_bip39_advanced(mnemonic, password)
    }
    /// Generate a new SLH-DSA5 secret key using BIP39 mnemonic without a password. This method allows for deterministic key generation based on a mnemonic phrase without the need for an additional password, making it suitable for scenarios where simplicity is preferred.
    pub fn generate_with_bip39_no_password(mnemonic: SlugMnemonic) -> SLHDSA5SecretKey {
        SLHDSA5SecretKey::generate_with_bip39_advanced(mnemonic, "")
    }
    /// Generate a new SLH-DSA5 secret key using BIP39 mnemonic and password, returning both the mnemonic and the secret key. This method allows for deterministic key generation based on a mnemonic phrase and an optional password, making it suitable for backup and recovery scenarios.
    pub fn generate_with_bip39_and_return_mnemonic(words: SlugBIP39Words, language: SlugBIP39Languages, password: &str) -> (SlugMnemonic, SLHDSA5SecretKey) {
        // Generate the mnemonic first, then derive the seed and generate the secret key from it.
        let mnemonic: SlugMnemonic = SlugMnemonic::new(words, language);

        // Clone the mnemonic to return it while consuming a copy to generate the key.
        (mnemonic.clone(), SLHDSA5SecretKey::generate_with_bip39_advanced(mnemonic, password))
    }
    /// Generate a new SLH-DSA5 secret key using BIP39 mnemonic without a password, returning both the mnemonic and the secret key. This method allows for deterministic key generation based on a mnemonic phrase without the need for an additional password, making it suitable for scenarios where simplicity is preferred.
    pub fn generate_with_bip39_no_password_and_return_mnemonic(words: SlugBIP39Words, language: SlugBIP39Languages) -> (SlugMnemonic, SLHDSA5SecretKey) {
        let mnemonic = SlugMnemonic::new(words, language);
        (mnemonic.clone(), SLHDSA5SecretKey::generate_with_bip39_advanced(mnemonic, ""))
    }
}

impl SLHDSA5SecretKey {
    /// Generate a new SLH-DSA5 secret key using the thread RNG. This method is suitable for general use cases where high-quality randomness is required.
    pub fn generate_using_threadrng() -> Self {
        let mut rng = rand_2::rng();    
        let signing_key = SigningKey::<Shake256s>::new(&mut rng);
        let bytes = signing_key.to_vec();

        let mut sk = [0u8; 128];
        sk.copy_from_slice(&bytes[0..128]);

        return SLHDSA5SecretKey::from_bytes(&sk).unwrap()
    }
    /// Generate a new SLH-DSA5 secret key using BIP39 mnemonic and password. This method allows for deterministic key generation based on a mnemonic phrase and an optional password, making it suitable for backup and recovery scenarios.
    pub fn generate_with_bip39_advanced(mnemonic: SlugMnemonic, pass: &str) -> SLHDSA5SecretKey {
        let mut rng: MnemnonicSeed = mnemonic.to_seed_with_crypto(pass).unwrap();
        let signing_key = SigningKey::<Shake256s>::new(&mut rng);
        let bytes = signing_key.to_vec();

        let mut sk = [0u8; 128];
        sk.copy_from_slice(&bytes[0..128]);

        return SLHDSA5SecretKey::from_bytes(&sk).unwrap()
    }
    /// Generate a new SLH-DSA5 secret key using BIP39 mnemonic and password, returning both the mnemonic and the secret key. This method allows for deterministic key generation based on a mnemonic phrase and an optional password, making it suitable for backup and recovery scenarios.
    pub fn generate_with_bip39(number_of_words: SlugBIP39Words, language: SlugBIP39Languages, pass: &str) -> (SlugMnemonic, SLHDSA5SecretKey) {
        let x: SlugMnemonic = SlugMnemonic::new(number_of_words, language);
        let mut rng: MnemnonicSeed = x.to_seed_with_crypto(pass).unwrap();
        let signing_key = SigningKey::<Shake256s>::new(&mut rng);
        let bytes = signing_key.to_vec();

        let mut sk = [0u8; 128];
        sk.copy_from_slice(&bytes[0..128]);

        return (x, SLHDSA5SecretKey::from_bytes(&sk).unwrap())
    }
    /// Generate a new SLH-DSA5 secret key using BIP39 mnemonic without a password, returning both the mnemonic and the secret key. This method allows for deterministic key generation based on a mnemonic phrase without the need for an additional password, making it suitable for scenarios where simplicity is preferred.
    pub fn generate_with_bip39_no_password(number_of_words: SlugBIP39Words, language: SlugBIP39Languages) -> (SlugMnemonic, SLHDSA5SecretKey) {
        return Self::generate_with_bip39(number_of_words, language, "");
    }
    /// Generate a new SLH-DSA5 secret key using BIP39 mnemonic and password. This method allows for deterministic key generation based on a mnemonic phrase and an optional password, making it suitable for backup and recovery scenarios.
    pub fn from_bip39(mnemonic: SlugMnemonic, password: &str) -> SLHDSA5SecretKey {
        Self::generate_with_bip39_advanced(mnemonic, password)
    }
    //=====BYTES======//
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SlugErrors> {
        if bytes.len() == 128 {
            let mut sk_array: [u8; 128] = [0u8; 128];
            sk_array.copy_from_slice(bytes);
            Ok(Self { sk: sk_array })
        }
        else {
            return Err(SlugErrors::Unknown)
        }
    }
    pub fn to_bytes(&self) -> [u8; 128] {
        return self.sk
    }
    pub fn as_bytes(&self) -> &[u8] {
        return &self.sk
    }
    pub fn to_vec(&self) -> Vec<u8> {
        return self.sk.to_vec()
    }
    pub fn to_hybrid_array(&self) -> Result<Array<u8, U128>, SlugErrors> { 
        return Ok(Array::from(self.sk)) 
    }
    pub fn to_usable_type(&self) -> Result<SigningKey<Shake256s>,SlugErrors> {
        let y = self.to_hybrid_array()?;
        let x = SigningKey::<Shake256s>::try_from(y.as_slice());

        if x.is_err() {
            return Err(SlugErrors::Unknown)
        }
        else {
            return Ok(x.unwrap())
        }
    }
    /// Sign a message using the SLH-DSA5 secret key. This method produces a deterministic signature for the same message, ensuring that the same input will always yield the same signature.
    /// 
    /// # Arguments
    /// 
    /// - `message`: The message to be signed, which can be any type that can be referenced as a byte slice (e.g., `&[u8]`, `Vec<u8>`, `&str`).
    /// 
    /// # Returns
    /// 
    /// - `SLHDSA5Signature`: The resulting signature of the message, encapsulated in the `SLHDSA5Signature` structure.
    pub fn sign<T: AsRef<[u8]>>(&self, message: T) -> Result<SLHDSA5Signature, SlugErrors> {
        let sk = self.to_usable_type()?;       
        let sig = sk.sign(message.as_ref());
        let output = sig.to_bytes().to_vec();
        let mut sig_array: [u8; 29792] = [0u8; 29_792];
        sig_array.copy_from_slice(&output[0..29_792]);
        Ok(SLHDSA5Signature { sig: sig_array })
    }
    /// Sign a message using the SLH-DSA5 secret key with randomized signing. This method generates a unique signature for the same message each time it is called, providing enhanced security against certain types of attacks.
    /// 
    /// # Arguments
    /// 
    /// - `message`: The message to be signed, which can be any type that can be referenced as a byte slice (e.g., `&[u8]`, `Vec<u8>`, `&str`).
    pub fn sign_with_rng<T: AsRef<[u8]>>(&self, message: T) -> Result<SLHDSA5Signature, SlugErrors> {
        let mut rng = rand_2::rng();
        let sk = self.to_usable_type()?;
        let sig = sk.sign_with_rng(&mut rng,message.as_ref());       
        let output = sig.to_bytes().to_vec();
        let mut sig_array: [u8; 29792] = [0u8; 29_792];
        sig_array.copy_from_slice(&output[0..29_792]);
        Ok(SLHDSA5Signature { sig: sig_array })
    }
}

impl SLHDSA5PublicKey {
    /// from bytes (64-bytes)     
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SlugErrors> {
        if bytes.len() == 64 {
            let mut pk_array: [u8; 64] = [0u8; 64];
            pk_array.copy_from_slice(bytes);
            Ok(Self { pk: pk_array })
        }
        else {
            return Err(SlugErrors::Unknown)
        }
    }
    /// to bytes (64-bytes)
    pub fn to_bytes(&self) -> [u8; 64] {
        return self.pk
    }
    /// as bytes (64-bytes)
    pub fn as_bytes(&self) -> &[u8] {
        return &self.pk
    }
    /// to vector (64 bytes)
    pub fn to_vec(&self) -> Vec<u8> {
        return self.pk.to_vec()
    }
    /// to hybrid array (64 bytes)
    pub fn to_hybrid_array(&self) -> Result<Array<u8, U64>, SlugErrors> {
        let x = Array::slice_as_array(&self.pk);
        
        if x.is_some() {
            return Ok(x.unwrap().to_owned())
        }
        else {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
    /// to usable type (VerifyingKey<Shake256s>)
    pub fn to_usable_type(&self) -> Result<VerifyingKey<Shake256s>, SlugErrors> {
        let x = &self.to_hybrid_array()?;
        let output: Result<VerifyingKey<Shake<digest::typenum::UInt<digest::typenum::UInt<digest::typenum::UInt<digest::typenum::UInt<digest::typenum::UInt<digest::typenum::UInt<digest::typenum::UTerm, digest::typenum::B1>, digest::typenum::B0>, digest::typenum::B0>, digest::typenum::B0>, digest::typenum::B0>, digest::typenum::B0>, digest::typenum::UInt<digest::typenum::UInt<digest::typenum::UInt<digest::typenum::UInt<digest::typenum::UInt<digest::typenum::UInt<digest::typenum::UTerm, digest::typenum::B1>, digest::typenum::B0>, digest::typenum::B1>, digest::typenum::B1>, digest::typenum::B1>, digest::typenum::B1>>>, ed448::Error> = VerifyingKey::<Shake256s>::try_from(x.as_slice());

        if output.is_ok() {
            return Ok(output.unwrap())
        }
        else {
            return Err(SlugErrors::Unknown)
        }    
    }
    /// Verify a signature using the SLH-DSA5 public key. This method checks the validity of the provided signature against the given message, returning `true` if the signature is valid and `false` otherwise.
    pub fn verify_with_context<T: AsRef<[u8]>>(&self, msg: T, signature: SLHDSA5Signature, context: T) -> Result<bool, SlugErrors> {
        let x = self.to_usable_type().unwrap().try_verify_with_context(msg.as_ref(), context.as_ref(), &signature.to_usable_type());

        if x.is_ok() {
            return Ok(true)
        }
        else {
            return Ok(false)
        }
    }
    /// Verify a signature using the SLH-DSA5 public key without a context. This method checks the validity of the provided signature against the given message, returning `true` if the signature is valid and `false` otherwise.
    /// 
    /// # Arguments
    /// 
    /// - `message`: The message to be signed, which can be any type that can be referenced as a byte slice (e.g., `&[u8]`, `Vec<u8>`, `&str`).
    /// 
    /// - `signature`: The signature to be verified, which should be an instance of `SLHDSA5Signature`.
    /// 
    /// # Returns
    /// 
    /// - `bool`: Returns `true` if the signature is valid for the given message and public key, and `false` otherwise.
    /// 
    /// # Context
    /// 
    /// The context used is a fixed 32-byte array of zeros (`[0u8; 32]`), which is a common practice for SLH-DSA when no specific context is provided. This ensures that the verification process is consistent and does not rely on any external context information.
    pub fn verify<T: AsRef<[u8]>>(&self, msg: T, signature: SLHDSA5Signature) -> Result<bool, SlugErrors> {
        let x = self.to_usable_type().unwrap().try_verify_with_context(msg.as_ref(), &[0u8; 32], &signature.to_usable_type());

        if x.is_ok() {
            return Ok(true)
        }
        else {
            return Ok(false)
        }
    }
}

impl SLHDSA5Signature {
    /// to usable type (slh_dsa::Signature<Shake256s>)
    pub fn to_usable_type(&self) -> Signature<Shake256s> {
        let x = Signature::<Shake256s>::try_from(self.sig.as_slice());

        if x.is_err() {
            panic!("Failed to convert SLHDSA5Signature to usable type: {:?}", x.err());
        }
        else {
            return x.unwrap()
        }
    }
    pub fn to_bytes(&self) -> [u8; 29_792] {
        return self.sig
    }
    pub fn as_bytes(&self) -> &[u8] {
        return &self.sig
    }
    pub fn to_vec(&self) -> Vec<u8> {
        return self.sig.to_vec()
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SlugErrors> {
        if bytes.len() == 29_792 {
            let mut sig_array: [u8; 29_792] = [0u8; 29_792];
            sig_array.copy_from_slice(bytes);
            Ok(Self { sig: sig_array })
        }
        else {
            Err(SlugErrors::Unknown)
        }
    }
}

impl SLHDSA5SignatureCID {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SlugErrors> {
        if bytes.len() <= 64 {
            let mut sig_array: [u8; 64] = [0u8; 64];
            sig_array.copy_from_slice(bytes);
            Ok(Self { cid: sig_array })
        }
        else {
            Err(SlugErrors::Unknown)
        }
    }   
}

//=====BINCODE======//

impl IntoBincode for SLHDSA5PublicKey {
    fn into_bincode(&self) -> Result<Vec<u8>, SlugErrors> {
        let x = bincode::serialize(self);

        if x.is_ok() {
            return Ok(x.unwrap())
        }
        else {
            return Err(SlugErrors::Unknown)
        }
    }
}

impl FromBincode for SLHDSA5PublicKey {
    fn from_bincode<T: AsRef<[u8]>>(bytes: T) -> Result<Self, SlugErrors> {
        let x = bincode::deserialize(bytes.as_ref());

        if x.is_ok() {
            return Ok(x.unwrap())
        }
        else {
            return Err(SlugErrors::Unknown)
        }
    }
}

impl IntoBincode for SLHDSA5SecretKey {
    fn into_bincode(&self) -> Result<Vec<u8>, SlugErrors> {
        let x = bincode::serialize(self);

        if x.is_ok() {
            return Ok(x.unwrap())
        }
        else {
            return Err(SlugErrors::Unknown)
        }
    }
}

impl FromBincode for SLHDSA5SecretKey {
    fn from_bincode<T: AsRef<[u8]>>(bytes: T) -> Result<Self, SlugErrors> {
        let x = bincode::deserialize(bytes.as_ref());

        if x.is_ok() {
            return Ok(x.unwrap())
        }
        else {
            return Err(SlugErrors::Unknown)
        }
    }
}

impl IntoBincode for SLHDSA5Signature {
    fn into_bincode(&self) -> Result<Vec<u8>, SlugErrors> {
        let x = bincode::serialize(self);

        if x.is_ok() {
            return Ok(x.unwrap())
        }
        else {
            return Err(SlugErrors::Unknown)
        }
    }
}

impl FromBincode for SLHDSA5Signature {
    fn from_bincode<T: AsRef<[u8]>>(bytes: T) -> Result<Self, SlugErrors> {
        let x = bincode::deserialize(bytes.as_ref());

        if x.is_ok() {
            return Ok(x.unwrap())
        }
        else {
            return Err(SlugErrors::Unknown)
        }
    }
}

impl IntoBincode for SLHDSA5SignatureCID {
    fn into_bincode(&self) -> Result<Vec<u8>, SlugErrors> {
        let x = bincode::serialize(self);

        if x.is_ok() {
            return Ok(x.unwrap())
        }
        else {
            return Err(SlugErrors::Unknown)
        }
    }
}

impl FromBincode for SLHDSA5SignatureCID {
    fn from_bincode<T: AsRef<[u8]>>(bytes: T) -> Result<Self, SlugErrors> {
        let x = bincode::deserialize(bytes.as_ref());

        if x.is_ok() {
            return Ok(x.unwrap())
        }
        else {
            return Err(SlugErrors::Unknown)
        }
    }
}

//=====END-OF-BINCODE======//

//=====ENCODING======//

impl IntoEncoding for SLHDSA5PublicKey {
    fn into_base32(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Base32).encode(&self.pk)?; 
        Ok(output)
    }
    fn into_base32_unpadded(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Base32unpadded).encode(&self.pk)?; 
        Ok(output)
    }
    fn into_base58(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Base58).encode(&self.pk)?; 
        Ok(output)
    }
    fn into_base64(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Base64).encode(&self.pk)?; 
        Ok(output)
    }
    fn into_base64_url_safe(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe).encode(&self.pk)?; 
        Ok(output)
    }
    fn into_hex(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Hex).encode(&self.pk)?; 
        Ok(output)
    }
}

impl FromEncoding for SLHDSA5PublicKey {
    fn from_base32<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let output: Vec<u8> = SlugEncodingUsage::new(SlugEncodings::Base32).decode(s.as_ref())?;
        Self::from_bytes(&output)
    }
    fn from_base32_unpadded<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let output: Vec<u8> = SlugEncodingUsage::new(SlugEncodings::Base32unpadded).decode(s.as_ref())?;
        Self::from_bytes(&output)
    }
    fn from_base58<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let output: Vec<u8> = SlugEncodingUsage::new(SlugEncodings::Base58).decode(s.as_ref())?;
        Self::from_bytes(&output)
    }
    fn from_base64<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let output: Vec<u8> = SlugEncodingUsage::new(SlugEncodings::Base64).decode(s.as_ref())?;
        Self::from_bytes(&output)
    }
    fn from_base64_url_safe<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let output: Vec<u8> = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe).decode(s.as_ref())?;
        Self::from_bytes(&output)
    }
    fn from_hex<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let output: Vec<u8> = SlugEncodingUsage::new(SlugEncodings::Hex).decode(s.as_ref())?;
        Self::from_bytes(&output)
    }
}

impl IntoEncoding for SLHDSA5SecretKey {
    fn into_base32(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Base32).encode(&self.sk)?; 
        Ok(output)
    }
    fn into_base32_unpadded(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Base32unpadded).encode(&self.sk)?; 
        Ok(output)
    }
    fn into_base58(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Base58).encode(&self.sk)?; 
        Ok(output)
    }
    fn into_base64(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Base64).encode(&self.sk)?; 
        Ok(output)
    }
    fn into_base64_url_safe(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe).encode(&self.sk)?; 
        Ok(output)
    }
    fn into_hex(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Hex).encode(&self.sk)?; 
        Ok(output)
    }
}

impl FromEncoding for SLHDSA5SecretKey {
    fn from_base32<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let output: Vec<u8> = SlugEncodingUsage::new(SlugEncodings::Base32).decode(s.as_ref())?;
        Self::from_bytes(&output)
    }
    fn from_base32_unpadded<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let output: Vec<u8> = SlugEncodingUsage::new(SlugEncodings::Base32unpadded).decode(s.as_ref())?;
        Self::from_bytes(&output)
    }
    fn from_base58<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let output: Vec<u8> = SlugEncodingUsage::new(SlugEncodings::Base58).decode(s.as_ref())?;
        Self::from_bytes(&output)
    }
    fn from_base64<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let output: Vec<u8> = SlugEncodingUsage::new(SlugEncodings::Base64).decode(s.as_ref())?;
        Self::from_bytes(&output)
    }
    fn from_base64_url_safe<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let output: Vec<u8> = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe).decode(s.as_ref())?;
        Self::from_bytes(&output)
    }
    fn from_hex<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let output: Vec<u8> = SlugEncodingUsage::new(SlugEncodings::Hex).decode(s.as_ref())?;
        Self::from_bytes(&output)
    }
}

impl IntoEncoding for SLHDSA5Signature {
    fn into_base32(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Base32).encode(&self.sig)?; 
        Ok(output)
    }
    fn into_base32_unpadded(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Base32unpadded).encode(&self.sig)?; 
        Ok(output)
    }
    fn into_base58(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Base58).encode(&self.sig)?; 
        Ok(output)
    }
    fn into_base64(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Base64).encode(&self.sig)?; 
        Ok(output)
    }
    fn into_base64_url_safe(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe).encode(&self.sig)?; 
        Ok(output)
    }
    fn into_hex(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Hex).encode(&self.sig)?; 
        Ok(output)
    }
}

impl FromEncoding for SLHDSA5Signature {
    fn from_base32<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let output: Vec<u8> = SlugEncodingUsage::new(SlugEncodings::Base32).decode(s.as_ref())?;
        Self::from_bytes(&output)
    }
    fn from_base32_unpadded<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let output: Vec<u8> = SlugEncodingUsage::new(SlugEncodings::Base32unpadded).decode(s.as_ref())?;
        Self::from_bytes(&output)
    }
    fn from_base58<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let output: Vec<u8> = SlugEncodingUsage::new(SlugEncodings::Base58).decode(s.as_ref())?;
        Self::from_bytes(&output)
    }
    fn from_base64<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let output: Vec<u8> = SlugEncodingUsage::new(SlugEncodings::Base64).decode(s.as_ref())?;
        Self::from_bytes(&output)
    }
    fn from_base64_url_safe<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let output: Vec<u8> = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe).decode(s.as_ref())?;
        Self::from_bytes(&output)
    }
    fn from_hex<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let output: Vec<u8> = SlugEncodingUsage::new(SlugEncodings::Hex).decode(s.as_ref())?;
        Self::from_bytes(&output)
    }
}

impl IntoEncoding for SLHDSA5SignatureCID {
    fn into_base32(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Base32).encode(&self.cid)?; 
        Ok(output)
    }
    fn into_base32_unpadded(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Base32unpadded).encode(&self.cid)?; 
        Ok(output)
    }
    fn into_base58(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Base58).encode(&self.cid)?; 
        Ok(output)
    }
    fn into_base64(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Base64).encode(&self.cid)?; 
        Ok(output)
    }
    fn into_base64_url_safe(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe).encode(&self.cid)?; 
        Ok(output)
    }
    fn into_hex(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Hex).encode(&self.cid)?; 
        Ok(output)
    }
}

impl FromEncoding for SLHDSA5SignatureCID {
    fn from_base32<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let output: Vec<u8> = SlugEncodingUsage::new(SlugEncodings::Base32).decode(s.as_ref())?;
        Self::from_bytes(&output)
    }
    fn from_base32_unpadded<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let output: Vec<u8> = SlugEncodingUsage::new(SlugEncodings::Base32unpadded).decode(s.as_ref())?;
        Self::from_bytes(&output)
    }
    fn from_base58<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let output: Vec<u8> = SlugEncodingUsage::new(SlugEncodings::Base58).decode(s.as_ref())?;
        Self::from_bytes(&output)
    }
    fn from_base64<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let output: Vec<u8> = SlugEncodingUsage::new(SlugEncodings::Base64).decode(s.as_ref())?;
        Self::from_bytes(&output)
    }
    fn from_base64_url_safe<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let output: Vec<u8> = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe).decode(s.as_ref())?;
        Self::from_bytes(&output)
    }
    fn from_hex<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let output: Vec<u8> = SlugEncodingUsage::new(SlugEncodings::Hex).decode(s.as_ref())?;
        Self::from_bytes(&output)
    }
}

//=====END-OF-ENCODING======//

//=====IntoStandardPEM=====//

impl IntoStandardPem for SLHDSA5PublicKey {
    fn into_standard_pem(&self) -> Result<String,SlugErrors> {
        let x = self.into_bincode()?;
        let pem = Pem::new(&Self::label_for_standard_pem(), x);
        return Ok(pem.to_string())
    }
    fn label_for_standard_pem() -> String {
        String::from("OpenInternetCryptographyProject/Standard/SLH-DSA5-SHAKE256-Public-Key")
    }
    fn label_for_standard_pem_secret() -> String {
        String::from("OpenInternetCryptographyProject/Standard/SLH-DSA5-SHAKE256-Secret-Key")
    }
}

impl FromStandardPem for SLHDSA5PublicKey {
    fn from_standard_pem<T: AsRef<str>>(pem_str: T) -> Result<Self,SlugErrors> {
        let pem = Pem::from_str(pem_str.as_ref()).map_err(|_| SlugErrors::Unknown)?;
        if pem.tag() != Self::label_for_standard_pem() {
            return Err(SlugErrors::Unknown)
        }
        Self::from_bincode(pem.contents())
    }
}

impl IntoStandardPem for SLHDSA5SecretKey {
    fn into_standard_pem(&self) -> Result<String,SlugErrors> {
        let x = self.into_bincode()?;
        let pem = Pem::new(&Self::label_for_standard_pem_secret(), x);
        return Ok(pem.to_string())
    }
    fn label_for_standard_pem() -> String {
        String::from("OpenInternetCryptographyProject/Standard/SLH-DSA5-SHAKE256-Secret-Key")
    }
    fn label_for_standard_pem_secret() -> String {
        String::from("OpenInternetCryptographyProject/Standard/SLH-DSA5-SHAKE256-Secret-Key")
    }
}

impl FromStandardPem for SLHDSA5SecretKey {
    fn from_standard_pem<T: AsRef<str>>(pem_str: T) -> Result<Self,SlugErrors> {
        let pem = Pem::from_str(pem_str.as_ref()).map_err(|_| SlugErrors::Unknown)?;
        if pem.tag() != Self::label_for_standard_pem_secret() {
            return Err(SlugErrors::Unknown)
        }
        Self::from_bincode(pem.contents())
    }
}

impl IntoStandardPem for SLHDSA5Signature {
    fn into_standard_pem(&self) -> Result<String,SlugErrors> {
        let x = self.into_bincode()?;
        let pem = Pem::new(&Self::label_for_standard_pem(), x);
        return Ok(pem.to_string())
    }
    fn label_for_standard_pem() -> String {
        String::from("OpenInternetCryptographyProject/Standard/SLH-DSA5-SHAKE256-Signature")
    }
    fn label_for_standard_pem_secret() -> String {
        String::from("OpenInternetCryptographyProject/Standard/SLH-DSA5-SHAKE256-Secret-Key")
    }
}

impl FromStandardPem for SLHDSA5Signature {
    fn from_standard_pem<T: AsRef<str>>(pem_str: T) -> Result<Self,SlugErrors> {
        let pem = Pem::from_str(pem_str.as_ref()).map_err(|_| SlugErrors::Unknown)?;
        if pem.tag() != Self::label_for_standard_pem() {
            return Err(SlugErrors::Unknown)
        }
        Self::from_bincode(pem.contents())
    }
}

impl IntoStandardPem for SLHDSA5SignatureCID {
    fn into_standard_pem(&self) -> Result<String,SlugErrors> {
        let x = self.into_bincode()?;
        let pem = Pem::new(&Self::label_for_standard_pem(), x);
        return Ok(pem.to_string())
    }
    fn label_for_standard_pem() -> String {
        String::from("OpenInternetCryptographyProject/Standard/SLH-DSA5-SHAKE256-Signature-CID")
    }
    fn label_for_standard_pem_secret() -> String {
        String::from("OpenInternetCryptographyProject/Standard/SLH-DSA5-SHAKE256-Secret-Key")
    }
}

impl FromStandardPem for SLHDSA5SignatureCID {
    fn from_standard_pem<T: AsRef<str>>(pem_str: T) -> Result<Self,SlugErrors> {
        let pem = Pem::from_str(pem_str.as_ref()).map_err(|_| SlugErrors::Unknown)?;
        if pem.tag() != Self::label_for_standard_pem() {
            return Err(SlugErrors::Unknown)
        }
        Self::from_bincode(pem.contents())
    }
}

//=====END-OF-StandardPEM=====//
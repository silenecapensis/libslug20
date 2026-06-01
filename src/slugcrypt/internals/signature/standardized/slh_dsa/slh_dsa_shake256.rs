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

use digest::typenum::U64;
use securerand_rs::bip39::*;
use serde::{Serialize,Deserialize};
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


use slugencode::SlugEncodingUsage;
use rand::rngs::OsRng;
use rand::CryptoRng;

use rand_2::rngs::SysRng;

use hybird_array_four::{Array,ArraySize,ArrayN,AssocArraySize};

use crate::errors::SlugErrors;

pub mod info {
    pub const CIPHER_SUITE: &str = "OpenInternetCryptographyProject/Standardized/SLH-DSA5";
    pub const PROTOCOL_NAME: &str = "libslug20/slh_dsa_shake256_level_5";
    pub const PUBLIC_KEY_SIZE: usize = 64;
    pub const SECRET_KEY_SIZE: usize = 128;
    pub const SIGNATURE_SIZE: usize = 29_792;
}

#[derive(Debug, Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop, PartialEq, PartialOrd, Hash)]
pub struct SLHDSA5PublicKey {
    #[serde(with = "BigArray")]
    pub pk: [u8; 64]
}
#[derive(Debug, Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop, PartialEq, PartialOrd, Hash)]
pub struct SLHDSA5SecretKey {
    #[serde(with = "BigArray")]
    pub sk: [u8; 128]
}

#[derive(Debug, Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop, PartialEq, PartialOrd, Hash)]
pub struct SLHDSA5Signature {
    #[serde(with = "BigArray")]
    pub sig: [u8; 29_792]
}

pub struct GenerateSLHDSA5;

impl GenerateSLHDSA5 {
    pub fn generate() -> SLHDSA5SecretKey {
        SLHDSA5SecretKey::generate_using_threadrng()
    }
}

impl SLHDSA5SecretKey {

    pub fn generate_using_threadrng() -> Self {
        let mut rng = rand_2::rng();    
        let signing_key = slh_dsa::SigningKey::<Shake256s>::new(&mut rng);
        let bytes = signing_key.to_vec();

        let mut sk = [0u8; 128];
        sk.copy_from_slice(&bytes[0..128]);

        return SLHDSA5SecretKey::from_bytes(&sk).unwrap()
    }
    pub fn generate_with_bip39_advanced(mnemonic: SlugMnemonic, pass: &str) -> SLHDSA5SecretKey {
        let mut rng: MnemnonicSeed = mnemonic.to_seed_with_crypto(pass).unwrap();
        let signing_key = slh_dsa::SigningKey::<Shake256s>::new(&mut rng);
        let bytes = signing_key.to_vec();

        let mut sk = [0u8; 128];
        sk.copy_from_slice(&bytes[0..128]);

        return SLHDSA5SecretKey::from_bytes(&sk).unwrap()
    }
    pub fn generate_with_bip39(number_of_words: SlugBIP39Words, language: SlugBIP39Languages, pass: &str) -> (SlugMnemonic, SLHDSA5SecretKey) {
        let x: SlugMnemonic = SlugMnemonic::new(number_of_words, language);
        let mut rng: MnemnonicSeed = x.to_seed_with_crypto(pass).unwrap();
        let signing_key = slh_dsa::SigningKey::<Shake256s>::new(&mut rng);
        let bytes = signing_key.to_vec();

        let mut sk = [0u8; 128];
        sk.copy_from_slice(&bytes[0..128]);

        return (x, SLHDSA5SecretKey::from_bytes(&sk).unwrap())
    }
    pub fn generate_with_bip39_no_password(number_of_words: SlugBIP39Words, language: SlugBIP39Languages) -> (SlugMnemonic, SLHDSA5SecretKey) {
        return Self::generate_with_bip39(number_of_words, language, "");
    }
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
}

impl SLHDSA5PublicKey {
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
    pub fn to_bytes(&self) -> [u8; 64] {
        return self.pk
    }
    pub fn as_bytes(&self) -> &[u8] {
        return &self.pk
    }
    pub fn to_vec(&self) -> Vec<u8> {
        return self.pk.to_vec()
    }
    pub fn to_hybrid_array(&self) -> Result<Array<u8, U64>, SlugErrors> {
        let x = Array::slice_as_array(&self.pk);
        
        if x.is_some() {
            return Ok(x.unwrap().to_owned())
        }
        else {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
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
    pub fn verify<T: AsRef<[u8]>>(&self, msg: T, signature: SLHDSA5Signature) {
        let x = self.to_usable_type().unwrap().verify_strict(msg.as_ref(), &signature.to_usable_type()).unwrap();
    }
}
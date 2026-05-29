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

use securerand_rs::bip39::*;
use serde::{Serialize,Deserialize};
use zeroize::{Zeroize,ZeroizeOnDrop};
use serde_big_array::BigArray;
use slh_dsa::Shake256s;
use slh_dsa::*;
use slh_dsa::ParameterSet;
use slh_dsa::signature::Keypair;
use slh_dsa::signature::RandomizedSigner;
use slh_dsa::signature::Signer;
use slugencode::SlugEncodingUsage;
use rand::rngs::OsRng;
use rand::CryptoRng;

use rand_2::rngs::SysRng;

use hybird_array_four::{Array,ArraySize,ArrayN,AssocArraySize};

use crate::errors::SlugErrors;

pub mod info {
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

impl SLHDSA5SecretKey {
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
    pub fn into_usable_type(&self) -> Result<(),SlugErrors> {
        let bytes = Array::try_from(self.sk);

        if bytes.is_err() {
            return Err(SlugErrors::Unknown)
        }
        //let bytes = bytes.unwrap();
        //let signing_key = slh_dsa::SigningKey::<Shake256s>::from_bytes(&bytes).unwrap();
        //return Ok(signing_key)
        Ok(())
    }
    pub fn public_key(&self) -> SLHDSA5PublicKey {
        let sk = self.into_usable_type().unwrap();
        let pk = sk.verifying_key();
        let bytes = pk.to_vec();
        let mut pk_array = [0u8; 64];
        pk_array.copy_from_slice(&bytes[0..64]);
        return SLHDSA5PublicKey::from_bytes(&pk_array).unwrap()
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
}
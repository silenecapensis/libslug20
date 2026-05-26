//! # SLH-DSA (SPHINCS+)
//! 
//! ## Variants
//! 
//! s: small sigs, slow verifying
//! f: fast verifying, larger sigs
//! 
//! - SLH-DSA (Level 5) using SHAKE256s
//! - SLH-DSA (Level 5) using SHA2_256s
//! 
//! - SLH-DSA (Level 3) using SHAKE256s
//! - SLH-DSA (Level 3) using SHA2_256s
//! 
//! ## TODO:
//! 
//! - [ ] Add support for SLH-DSA (Level 5) using SHAKE256s

use slh_dsa::Shake256s;
use slh_dsa::Sha2_256s;
use slh_dsa::*;
use slh_dsa::ParameterSet;
use slh_dsa::signature::Keypair;
use slh_dsa::signature::RandomizedSigner;
use slh_dsa::signature::Signer;

use securerand_rs::securerand::SecureRandom;
use securerand_rs::rngs::FuschineCSPRNG;

use serde::{Serialize,Deserialize};
use zeroize::{Zeroize,ZeroizeOnDrop};
use serde_big_array::BigArray;

/// RAND
use rand_2;

use securerand_rs::bip39::*;

/// # SLHDSA Types
/// 
/// SLHDSA Types are the variants of SLH-DSA.
#[derive(Debug, Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop, PartialEq, PartialOrd, Hash)]
pub enum SLHDSATypes {
    /// SLH-DSA (Level 5) using SHAKE256s
    SLHDSA5_SHAKE256,
    /// SLH-DSA (Level 5) using SHA2_256s
    SLHDSA5_SHA2_256,
    /// SLH-DSA (Level 3) using SHAKE256s
    SLHDSA3_SHAKE256,
    /// SLH-DSA (Level 3) using SHA2_256s
    SLHDSA3_SHA2_256
}

#[derive(Debug, Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop, PartialEq, PartialOrd, Hash)]
pub struct SLHDSAKeypair {
    pub pk: SLHDSAPublicKey5,
    pub sk: SLHDSASecretKey5,
}

#[derive(Debug, Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop, PartialEq, PartialOrd, Hash)]
pub struct SLHDSAPublicKey5 {
    #[serde(with = "BigArray")]
    pub pk: [u8; 64]
}
#[derive(Debug, Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop, PartialEq, PartialOrd, Hash)]
pub struct SLHDSASecretKey5 {
    #[serde(with = "BigArray")]
    pub sk: [u8; 128]
}

/// # SLHDSA Generate
/// 
/// Generate different variants of SLH-DSA.
pub struct SLHDSAGenerate;

impl SLHDSAGenerate {

    /// # Generation Using ThreadRNG
    /// 
    /// Generates a SLH-DSA keypair using ThreadRNG
    pub fn generate_using_threadrng() {
        let mut rng = rand_2::rng();    
        let signing_key = slh_dsa::SigningKey::<Shake256s>::new(&mut rng);
        let pk = signing_key.verifying_key();
    }
    pub fn generate_with_bip39_advanced(mnemonic: SlugMnemonic, pass: &str) {
        let mut rng: MnemnonicSeed = mnemonic.to_seed_with_crypto(pass).unwrap();
        let signing_key = slh_dsa::SigningKey::<Shake256s>::new(&mut rng);
        let pk = signing_key.verifying_key();
    }
    pub fn generate_with_bip39(number_of_words: SlugBIP39Words, language: SlugBIP39Languages, pass: &str) {
        let x: SlugMnemonic = SlugMnemonic::new(number_of_words, language);
        let mut rng: MnemnonicSeed = x.to_seed_with_crypto(pass).unwrap();
        let signing_key = slh_dsa::SigningKey::<Shake256s>::new(&mut rng);
        let pk = signing_key.verifying_key();
    }
    pub fn generate_with_bip39_no_password(number_of_words: SlugBIP39Words, language: SlugBIP39Languages) {
        Self::generate_with_bip39(number_of_words, language, "");
    }

}
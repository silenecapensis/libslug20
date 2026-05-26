//! # Add Hedged Signatures Using Cryptographic Randomness
//! 
//! 

pub trait HedgedSignatures {

}

use fixedstr::str64;
use fixedstr::str128;
use std::str::FromStr;

use securerand_rs::rngs::FuschineCSPRNG;
use slugencode::prelude::*;
use slugencode::SlugEncoder;

/// # Hedged Signature Data
/// 
/// This appends to the signature randomness that is created from OS entropy and from user-input, or os-salt.
pub struct HedgedSignatureData {
    pub oscsprng: str128,
    pub argon: str128,
}

impl HedgedSignatureData {
    pub fn new<T: AsRef<str>>(s: T) -> Self {
        // Generate Cryptographic Randomness
        let x = FuschineCSPRNG::get_32_bytes_from_os();

        let output = x.to_hex().unwrap();

        let argon_output = securerand_rs::securerand::SecureRandom::derive_from_password(s.as_ref());

        let password_output = argon_output.to_hex().unwrap();

        let oscsprng = str128::from_str(&password_output).unwrap();
        let argon = str128::from_str(&output).unwrap();

        Self {
            oscsprng: oscsprng,
            argon: argon,
        }

        
    }
}
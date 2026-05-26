//! # ShulginSigning
//! 
//! ShulginSigning is a hybrid digital signature scheme using ED25519 and SPHINCS+ (SHAKE256).
//! 
//! ## Encoding
//! 
//! ### Public Key
//! 
//! ED25519 (Upper-Hex) | : | SPHINCS+ PK (Upper-Hex)
//! 
//! #### Length
//! 
//! Length: 193 bytes
//! Length For ED25519: 32 * 2 = 64
//! Length For Colon: 1 byte
//! Length For SPHINCS+: 64 * 2 = 128
//! 
//! ### Signature
//! 
//! ED25519 (Upper-Hex) | : | SPHINCS+ Signature (Base58)
//! 
//! It is created by Joseph P. Tortorelli (silene/0x20CB)
//! 
//! ## TODO:
//! 
//! - [ ] REFACTOR
//! - [ ] ENCODINGS
//! - [ ] PUBLIC KEY
//! - [ ] PRIVATE KEY
//! - [X] ADD PEM ENCODING
//! 
//! ## TODO:
//! - [X] Implement ShulgingSigning Scheme (with secure, hedged signatures)
//!     - [X] Argon2id/Rand
//! - [X] Signing with CSPRNG
//! - [X] Signing with Secure Entropy
//! 
//! ## Signing Suites
//! 
//! - [X] ShulginSigning
//!     - [X] Standard Signing
//! - [X] ShulginSigning-With-OSCSPRNG
//! - [X] Shulgin-Signing-With-Hedged-Signatures (default; most secure) (0x20CB/silene version)
//!     - [X] Ephermal Password Hashed With OS_SALT, Put Through Argon2id, Then Fed Into CHACHA20RNG For Randomness
//! - [ ] Shulgin-Signing-With-Hedged-Signatures-And-VRF

use std::f32::consts::E;
use std::str::FromStr;
use std::string::FromUtf8Error;

use crate::slugcrypt::internals::messages::Message;
use crate::slugcrypt::internals::signature::ed25519::{ED25519SecretKey,ED25519PublicKey,ED25519Signature};
use crate::slugcrypt::internals::signature::shulginsigning::protocol_values::{SHULGIN_SIGNING_X59_FORMAT_DELIMITER_POSITION, SHULGIN_SIGNING_X59_FORMAT_ED25519_HEX_LENGTH, SHULGIN_SIGNING_X59_FORMAT_FULL_DELIMITER_FOR_SK, SHULGIN_SIGNING_X59_FORMAT_FULL_LENGTH, SHULGIN_SIGNING_X59_FORMAT_FULL_SPLIT, SHULGIN_SIGNING_X59_FORMAT_LENGTH, SHULGIN_SIGNING_X59_FORMAT_SPHINCS_HEX_LENGTH, SHULGIN_SIGNING_X59_LABEL};
use crate::slugcrypt::internals::signature::sphincs_plus::{SPHINCSPublicKey,SPHINCSSecretKey,SPHINCSSignature};
use crate::errors::SlugErrors;
use crate::errors::SlugErrorAlgorithms;
use crate::slugcrypt::traits::{FromBincode,IntoBincode};


use fixedstr::str128;

use k256::pkcs8;
use slugencode::prelude::*;
use pem::Pem;

use serde::{Serialize,Deserialize};
use zeroize::{ZeroizeOnDrop,Zeroize};

// IntoPem
use crate::slugcrypt::traits::IntoPem;
use crate::slugcrypt::traits::{IntoX59PublicKey,IntoX59SecretKey,IntoX59Signature};
use crate::slugcrypt::traits::{IntoEncoding,FromEncoding};
use securerand_rs::securerand::SecureRandom;
use securerand_rs::rngs::FuschineCSPRNG;
use crate::slugcrypt::traits::{FromStandardPem, IntoStandardPem};
use crate::slugcrypt::traits::{IntoStandardEncoding,FromStandardEncoding};

use serde_json;

pub mod protocol_values {
    pub const PROTOCOL_NAME_PUBLIC: &str = "ShulginSigning-Public-Key";
    pub const PROTOCOL_NAME_SECRET: &str = "ShulginSigning-Secret-Key";
    pub const PROTOCOL_NAME_SIGNATURE: &str = "ShulginSigning-Signature";

    pub const SHULGIN_SIGNING_X59_FORMAT_LENGTH: usize = 193;
    pub const SHULGIN_SIGNING_X59_FORMAT_FULL_SPLIT: usize = 193;


    pub const SHULGIN_SIGNING_X59_FORMAT_FULL_DELIMITER_FOR_SK: usize = 64;
    // Delimiter is a colon
    pub const SHULGIN_SIGNING_X59_FORMAT_DELIMITER_POSITION: usize = 64;
    
    pub const SHULGIN_SIGNING_X59_FORMAT_ED25519_HEX_LENGTH: usize = 64;
    pub const SHULGIN_SIGNING_X59_FORMAT_SPHINCS_HEX_LENGTH: usize = 128;

    pub const SHULGIN_SIGNING_X59_FORMAT_FULL_LENGTH: usize = 515;

    pub const SHULGIN_SIGNING_X59_LABEL: &str = "[libslug20/ShulginSigning]";
    pub const SHULGIN_SIGNING_X59_SUITE: &str = "ed25519_with_sphincs_shake256_255s_signature_scheme";
}

/// # ShulginKeypair
/// 
/// Contains an ED25519 Keypair and a SPHINCS+ Keypair
#[derive(Debug,Serialize,Deserialize,Clone,Zeroize,ZeroizeOnDrop,PartialEq,PartialOrd,Hash)]
pub struct ShulginKeypair {
    //=====Public-Keys=====//
    pub ed25519pk: ED25519PublicKey,
    pub sphincspk: SPHINCSPublicKey, // Post-Quantum
    
    //=====Secret-Keys=====//
    pub ed25519sk: Option<ED25519SecretKey>,
    pub sphincssk: Option<SPHINCSSecretKey>,
}

impl IntoX59PublicKey for ShulginKeypair {
    fn into_x59_pk(&self) -> Result<String,SlugErrors> {
        let x: Result<String, SlugEncodingError> = self.to_x59_pk_format();

        match x {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugErrors::Other(String::from("Failed To Convert ShulginSigning Into X59 Public Key Format.")))
        }
    }
    fn from_x59_pk<T: AsRef<str>>(x59_encoded: T) -> Result<Self,SlugErrors> {
        return Self::from_x59_pk_format(x59_encoded)
    }
    fn x59_metadata_pk() -> String {
        return String::from("libslug20/ShulginSigning")
    }
}

impl IntoX59SecretKey for ShulginKeypair {
    fn into_x59(&self) -> Result<String,SlugErrors> {

        let mut output: String = String::new();
        
        if self.ed25519sk.is_some() == true && self.sphincssk.is_some() == true {
            let ed25519pk = &self.ed25519pk.to_hexadecimal()?;
            let ed25519sk = &self.ed25519sk.clone().unwrap().to_hexadecimal()?;
            let sphincspk = &self.sphincspk.into_hex()?;;
            let sphincssk = &self.sphincssk.clone().unwrap().into_hex()?;;

            output.push_str(&ed25519pk);
            output.push_str(":");
            output.push_str(&sphincspk);
            output.push_str("/");
            output.push_str(ed25519sk);
            output.push_str(":");
            output.push_str(sphincssk);

            return Ok(output)

        }
        else {
            Err(SlugErrors::Other(String::from("Could Not Convert To X59")))
        }
    }
    fn from_x59<T: AsRef<str>>(x59_encoded_secret_key: T) -> Result<Self,SlugErrors> {
        let x: Option<(&str, &str)> = x59_encoded_secret_key.as_ref().split_once("/");

        if x.is_some() {
            let pk: &str = x.unwrap().0;
            let sk: &str = x.unwrap().1;

            let pk_keys: Option<(&str, &str)> = pk.split_once(":");
            let sk_keys: Option<(&str, &str)> = pk.split_once(":");

            if pk_keys.is_some() == true {
                let (ed25519_pk, sphincs_pk) = pk_keys.unwrap();

                if sk_keys.is_some() == true {
                    let (ed25519_sk, sphincs_sk) = sk_keys.unwrap();

                    let output_ed25519_pk = ED25519PublicKey::from_hex(ed25519_pk)?;
                    let output_sphincs_pk = SPHINCSPublicKey::from_hex_string_final(sphincs_pk)?;

                    let output_ed25519_sk = ED25519SecretKey::from_hex(ed25519_sk)?;
                    let output_sphincs_sk = SPHINCSSecretKey::from_hex(sphincs_sk)?;

                    return Ok(Self {
                        ed25519pk: output_ed25519_pk,
                        sphincspk: output_sphincs_pk,
                        ed25519sk: Some(output_ed25519_sk),
                        sphincssk: Some(output_sphincs_sk),
                    })
                }
                else {
                    return Err(SlugErrors::DecodingError { alg: SlugErrorAlgorithms::SIG_SHULGINSIGNING, encoding: crate::errors::EncodingError::X59_fmt, other: None })
                }
            }
            else {
                return Err(SlugErrors::DecodingError { alg: SlugErrorAlgorithms::SIG_SHULGINSIGNING, encoding: crate::errors::EncodingError::X59_fmt, other: None })
            }

        }
        else {
            return Err(SlugErrors::DecodingError { alg: SlugErrorAlgorithms::SIG_SHULGINSIGNING, encoding: crate::errors::EncodingError::X59_fmt, other: None })
        }
    }
    fn x59_metadata() -> String {
        return String::from("libslug20/ShulginSigning")
    }
}

impl ShulginKeypair {
    /// # To X59 Public Key Format
    /// 
    /// ## Description
    /// 
    /// ShulginSigning: `ED25519_PK(hex)` + `:` + `SPHINCS+_PK`
    /// 
    /// ## Info
    /// 
    /// **X59 Format Length:** 193 bytes
    /// **Constant-Time-Encoding:** True
    /// **Encodings:** Constant-Time Hexadecimal
    /// **ED25519 Length (In hexadecimal):** 64 bytes
    /// **SPHINCS+ Length (In Hexadecimal):** 128 bytes
    /// **Delimiter Length:** 1 byte
    pub fn to_x59_pk_format(&self) -> Result<String,SlugEncodingError> {
        let mut output = String::new();
        let x = SlugEncodingUsage::new(SlugEncodings::Hex);
        let ed25519 = x.encode(self.ed25519pk.as_bytes())?;
        let sphincs = x.encode(self.sphincspk.as_bytes())?;

        output.push_str(&ed25519);
        output.push_str(":");
        output.push_str(&sphincs);

        assert_eq!(output.len(),SHULGIN_SIGNING_X59_FORMAT_LENGTH);

        return Ok(output)
    }
    /// # From X59 Public Key Format
    /// 
    /// ShulginSigning: `ED25519_PK(hex)` + `:` + `SPHINCS+_PK`
    /// 
    /// ## Info
    /// 
    /// **X59 Format Length:** 193 bytes
    /// **Constant-Time-Encoding:** True
    /// **Encodings:** Constant-Time Hexadecimal
    /// **ED25519 Length (In hexadecimal):** 64 bytes
    /// **SPHINCS+ Length (In Hexadecimal):** 128 bytes
    /// **Delimiter Length:** 1 byte
    pub fn from_x59_pk_format<T: AsRef<str>>(x59_encoded: T) -> Result<ShulginKeypair, SlugErrors> {
        let x = x59_encoded.as_ref();
        let delimiter_position = x.find(":").expect("Expected to find colon at certain position");
        
        if x.len() == SHULGIN_SIGNING_X59_FORMAT_LENGTH && x.contains(":") == true && delimiter_position == SHULGIN_SIGNING_X59_FORMAT_DELIMITER_POSITION {
            let (ed25519_hex, sphincs_plus_hex) = x.split_at_checked(SHULGIN_SIGNING_X59_FORMAT_DELIMITER_POSITION).expect("Failed To Get ShulginSigning Sig");

            let sphincs_plus_hex_edited = remove_first(sphincs_plus_hex).unwrap();

            assert_eq!(ed25519_hex.len(), SHULGIN_SIGNING_X59_FORMAT_ED25519_HEX_LENGTH);
            assert_eq!(sphincs_plus_hex_edited.len(), SHULGIN_SIGNING_X59_FORMAT_SPHINCS_HEX_LENGTH);
            let pk: Result<ED25519PublicKey, SlugEncodingError> = ED25519PublicKey::from_hex(ed25519_hex);
            let pk_sphincs: Result<SPHINCSPublicKey, SlugErrors> = SPHINCSPublicKey::from_hex(sphincs_plus_hex_edited);

            let ed25519_output_pk = match pk {
                Ok(v) => v,
                Err(_) => return Err(SlugErrors::Other(String::from("Issue with ED25519 Public Key Conversion.")))
            };
            let sphincs_output_pk = match pk_sphincs {
                Ok(v) => v,
                Err(_) => return Err(SlugErrors::Other(String::from("Issue with SPHINCS+ Public Key Conversion.")))
            };

            return Ok(
                Self {
                    ed25519pk: ed25519_output_pk,
                    sphincspk: sphincs_output_pk,
                    ed25519sk: None,
                    sphincssk: None,
                }
            )
        }
        else {
            return Err(SlugErrors::Other(String::from("Incorrect X59 Format For Parsing ShulginSigning Public Key")))
        }
    }
    /// # X59 Metadata
    /// 
    /// Contains: `[libslug20/ShulginSigning]`
    pub fn into_x59_metadata() -> String {
        return SHULGIN_SIGNING_X59_LABEL.to_string()
    }
    /// # X59 Secret
    /// 
    /// ED25519PK:SPHINCSPK/ED25519SK:SPHINCSSK
    /// 
    /// **X59 Format Length:** 515 bytes
    /// **Constant-Time-Encoding:** True
    /// **ED25519 PK Length (In Hexadecimal):** 64 bytes
    /// **SPHINCS+ PK Length (In Hexadecimal):** 128 bytes
    /// **ED25519 SK Length (In Hexadecimal): 64 bytes
    /// **SPHINCS+ SK Length (In Hexadecimal): 256 bytes.
    /// **Total Bytes: 512**
    /// **Additional Bytes:** 3 (`: / :`)
    /// **Delimiter For Public Key vs. Private Key:** `/`
    /// **Delimiter For Other:** `:`
    pub fn to_x59_format_full(&self) -> Result<String,SlugErrors> {
        if self.ed25519sk.is_none() || self.sphincssk.is_none() {
            return Err(SlugErrors::Other(String::from("There are no secret keys provided.")))
        }
        else {
            //
        }
        let mut output: String = String::new();

        output.push_str(&self.ed25519pk.to_hexadecimal().expect("Failed To Get ED25519 Public Key"));
        output.push_str(":");
        output.push_str(&self.sphincspk.into_hex().expect("Failed To Convert To Hexadecimal For SPHINCS+ Public Key"));

        output.push_str("/");

        output.push_str(&self.ed25519sk.clone().unwrap().to_hexadecimal().unwrap());
        output.push_str(":");
        output.push_str(&self.sphincssk.clone().unwrap().into_hex().unwrap());

        return Ok(output)
    }
    /// # From X59 Secret
    /// 
    /// ED25519PK:SPHINCSPK/ED25519SK:SPHINCSSK
    /// 
    /// **X59 Format Length:** 515 bytes
    /// **Constant-Time-Encoding:** True
    /// **ED25519 PK Length (In Hexadecimal):** 64 bytes
    /// **SPHINCS+ PK Length (In Hexadecimal):** 128 bytes
    /// **ED25519 SK Length (In Hexadecimal): 64 bytes
    /// **SPHINCS+ SK Length (In Hexadecimal): 256 bytes.
    /// **Total Bytes: 512**
    /// **Additional Bytes:** 3 (`: / :`)
    /// **Delimiter For Public Key vs. Private Key:** `/`
    /// **Delimiter For Other:** `:`
    pub fn from_x59_format_full<T: AsRef<str>>(full_encoded_x59_string: T) -> Result<Self,SlugErrors> {
        let x = full_encoded_x59_string.as_ref();
        
        
        if x.len() == SHULGIN_SIGNING_X59_FORMAT_FULL_LENGTH && x.contains(":") == true && x.contains("/") == true {
            let (pk, _sk) = x.split_at_checked(SHULGIN_SIGNING_X59_FORMAT_FULL_SPLIT).unwrap();

            let sk = remove_first(_sk).unwrap();
            //let pk_2 = pk.replace("/","");

            let (ed25519, _sphincs) = pk.split_at_checked(SHULGIN_SIGNING_X59_FORMAT_DELIMITER_POSITION).unwrap();
            let (ed25519_sk, _sphincs_sk) = sk.split_at_checked(SHULGIN_SIGNING_X59_FORMAT_FULL_DELIMITER_FOR_SK).unwrap();

            let sphincs = remove_first(_sphincs).unwrap();
            let sphincs_sk = remove_first(_sphincs_sk).unwrap();

            let x = ED25519PublicKey::from_hex(ed25519);
            let y = SPHINCSPublicKey::from_hex(sphincs);

            let output_ed25519: ED25519PublicKey = match x {
                Ok(x) => x,
                Err(_) => return Err(SlugErrors::Other(String::from("ED25519 Public Key Failure")))
            };
            let output_sphincs: SPHINCSPublicKey = match y {
                Ok(y) => y,
                Err(_) => return Err(SlugErrors::Other(String::from("SPHINCS+ Public Key Failure")))
            };

            let n = ED25519SecretKey::from_hex(ed25519_sk);
            let m = SPHINCSSecretKey::from_hex(sphincs_sk);

            let output_ed25519_sk = match n {
                Ok(v) => v,
                Err(_) => return Err(SlugErrors::Other(String::from("Issue With ED25519 Parsing")))
            };

            let output_sphincs_sk = match m {
                Ok(v) => v,
                Err(_) => return Err(SlugErrors::Other(String::from("Issue With SPHINCS+ Parsing")))
            };

            return Ok(
                Self {
                    ed25519pk: output_ed25519,
                    sphincspk: output_sphincs,
                    ed25519sk: Some(output_ed25519_sk),
                    sphincssk: Some(output_sphincs_sk)
                }
            )
        }
        else {
            return Err(SlugErrors::Other(String::from("Could Not Parse. Error In Parsing For ShulginSigning X59 Format.")))
        }
    }
    pub fn into_public_key(&self) -> Self {
        return Self {
            ed25519pk: self.ed25519pk.clone(),
            sphincspk: self.sphincspk.clone(),
            ed25519sk: None,
            sphincssk: None,
        }
    }
}

#[derive(Debug,Serialize,Deserialize,Clone,Zeroize,ZeroizeOnDrop,PartialEq,PartialOrd,Hash)]
pub struct ShulginSigningPublicKey {
    pub clpk: ED25519PublicKey,
    pub pqpk: SPHINCSPublicKey,
}

#[derive(Debug,Serialize,Deserialize,Clone,Zeroize,ZeroizeOnDrop,PartialEq,PartialOrd,Hash)]
pub struct ShulginSigningSecretKey {
    pub clsk: ED25519SecretKey,
    pub pqpk: SPHINCSPublicKey,
    pub pqsk: SPHINCSSecretKey,
}

/// # ShulginSigning Compact
#[derive(Debug,Serialize,Deserialize,Clone,Zeroize,ZeroizeOnDrop, PartialEq, PartialOrd, Hash)]
pub struct ShulginKeypairCompact {
    pub public_key: String,
    pub secret_key: Option<String>,
}

impl ShulginKeypairCompact {
    pub fn from_pk(keypair: &ShulginKeypair) -> Result<Self,SlugErrors> {
        let pk = key_to_compact(&keypair);

        if pk.is_err() {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
        else {
            return Ok(Self { public_key: pk.unwrap(), secret_key: None })
        }
    }
    pub fn from_sk(keypair: &ShulginKeypair) -> Result<Self, SlugErrors> {
        let pk = key_to_compact(keypair);
        let sk = secret_key_to_compact(keypair);

        if pk.is_err() || sk.is_err() {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
        else {
            return Ok(Self {
                public_key: pk.unwrap(),
                secret_key: Some(sk.unwrap())
            })
        }
    }
    pub fn as_str_pk(&self) -> &str {
        return &self.public_key
    }
    pub fn to_str_pk(&self) -> String {
        return self.public_key.clone()
    }
    pub fn to_str_sk(&self) -> String {
        return self.secret_key.clone().unwrap()
    }
    pub fn contains_secret(&self) -> bool {
        if self.secret_key.is_some() {
            return true
        }
        else {
            return false
        }
    }
    pub fn into_shulginkeypair(&self) -> Result<ShulginKeypair, SlugErrors> {
        if self.contains_secret() == false {
            return ShulginKeypair::from_compact_pk(&self.public_key)
        }
        else {
            return ShulginKeypair::from_compact_keypair(&self.public_key, &self.secret_key.clone().unwrap())
        }
    }
}

#[derive(Debug,Serialize,Deserialize,Clone,Zeroize,ZeroizeOnDrop, PartialEq, PartialOrd, Hash)]
pub struct ShulginSignature {
    pub clsig: ED25519Signature,
    pub pqsig: SPHINCSSignature,
}

/// # Implemented
/// 
/// ## Encoding
/// 
/// - Use Base32 (unpadded encoding)
/// 
/// ## Secure Randomness
/// 
/// - [ ] VRF
/// - [ ] OS_RANDOMNESS
/// - [ ] ARGON2ID (Password-Derived Ephermal ShulginSigning 0x20CB/Silene style)
#[derive(Clone, Serialize,Deserialize,PartialEq,PartialOrd,Eq,Ord, Debug)]
pub struct ShulginSignatureSigningInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vrf: Option<str128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os_randomness: Option<str128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    argon2id: Option<str128>,
}

impl ShulginSignatureSigningInfo {
    pub fn new() -> Self {
        let os_randomness = Self::generate_oscsprng();

        return Self {
            message: None,
            vrf: None,
            os_randomness: Some(os_randomness),
            argon2id: None
        }
    }
    /// # Serialize
    /// 
    /// Serializes To JSON. Used for Signing/Verifying.
    pub fn serialize(&self) -> Result<String,SlugErrors> {
        let x = serde_json::to_string(&self);

        match x {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugErrors::Other(String::from("Parsing Error In JSON")))
        }
    }
    pub fn new_with_hedged_signatures<T: AsRef<str>>(ephermal_pass: T) -> Self {
        let os_randomness = Self::generate_oscsprng();
        let argon2id = Self::generate_securerand(ephermal_pass);

        return Self {
            message: None,
            vrf: None,
            os_randomness: Some(os_randomness),
            argon2id: Some(argon2id),
        }
    }
    pub fn new_with_hedged_signatures_oscsprng() -> Self {
        let os_randomness = Self::generate_oscsprng();
        let seed = Self::generate_oscsprng();
        let argon2id = Self::generate_securerand(seed);

        return Self {
            message: None,
            vrf: None,
            os_randomness: Some(os_randomness),
            argon2id: Some(argon2id)
        }
    }
    fn generate_oscsprng() -> str128 {
        let encoder = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let os_randomness = FuschineCSPRNG::get_32_bytes_from_os();
        let output = encoder.encode(os_randomness).expect("Failed to encode randomness");
        let output_csprng = fixedstr::str128::from_str(&output).unwrap();
        return output_csprng
    }
    fn generate_securerand<T: AsRef<str>>(pass: T) -> str128 {
        let encoder = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let randomness = SecureRandom::new(pass.as_ref());
        let output = str128::from_str(&encoder.encode(randomness).unwrap()).unwrap();
        return output
    }
}
/*
/// # Compact Signature
/// 
/// SPHINCS+ is compact due to using hash to find signature.
pub struct ShulginSignatureCompact {
    pub clsig: ED25519Signature,
    pub pqsig_location: str128,
}
    */

#[derive(Debug,Serialize,Deserialize,Clone,Zeroize,ZeroizeOnDrop,PartialEq,PartialOrd,Hash)]
pub struct ShulginSignatureCompact {
    pub signature: String,
}

impl ShulginSignatureCompact {
    pub fn new(ed25519: ED25519Signature, sphincs: SPHINCSSignature) -> Self {
        let mut output: String = String::new();
        
        let delimiter = ":";

        let upper_ed25519_sig = ed25519.to_hex_string();
        let sphincs_sig_bs58 = sphincs.to_base58_string();

        output.push_str(&upper_ed25519_sig);
        output.push_str(delimiter);
        output.push_str(&sphincs_sig_bs58);

        return Self {
            signature: output
        }
    }
    pub fn as_string(&self) -> &str {
        &self.signature
    }
    pub fn to_string(&self) -> String {
        self.signature.clone()
    }
    pub fn from_str<T: AsRef<str>>(compact: T) -> Self {
        return Self {
            signature: compact.as_ref().to_string()
        }
    }
    pub fn into_shulginsignature(&self) -> Result<ShulginSignature, SlugErrors> {
        let manipulated_string = self.to_string();

        let keys: Vec<&str> = manipulated_string.split(":").collect();

        if keys.len() != 2 {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }

        let output_ed = ED25519Signature::from_hex_string(keys[0]);
        let output_sphincs = SPHINCSSignature::from_base58_string(keys[1]);

        if output_ed.is_err() {
            return Err(SlugErrors::VerifyingError(SlugErrorAlgorithms::SIG_ED25519))
        } 
        else if output_sphincs.is_err() {
            return Err(SlugErrors::VerifyingError(SlugErrorAlgorithms::SIG_SPHINCS_PLUS))
        }
        else {
            let output_sig_cl: ED25519Signature = ED25519Signature::from_bytes(&output_ed.unwrap())?;
            let output_sig_pq: SPHINCSSignature = SPHINCSSignature::from_bytes(&output_sphincs.unwrap())?;

            return Ok(ShulginSignature {
                clsig: output_sig_cl,
                pqsig: output_sig_pq,
        })
        }

    }
}

impl ShulginKeypair {
    pub fn add_secret(&mut self, ed25519secret: ED25519SecretKey, sphincssecret: SPHINCSSecretKey) {
        self.ed25519sk = Some(ed25519secret);
        self.sphincssk = Some(sphincssecret);
    }
    pub fn from_public_key(ed25519pk: &ED25519PublicKey, sphincspk: &SPHINCSPublicKey) -> Self {
        return Self {
            ed25519pk: ed25519pk.to_owned(),
            sphincspk: sphincspk.to_owned(),

            ed25519sk: None,
            sphincssk: None,
        }
    }
    /// # Generate ShulginSigning
    /// 
    /// Generates a new `ShulginSigning` Keypair that uses SPHINCS+ and ED25519
    pub fn generate() -> Self {
        let cl = ED25519SecretKey::generate();
        let clpk = cl.public_key().unwrap();
        let (pq_pk,pq_sk) = SPHINCSSecretKey::generate();

        return Self {
            ed25519pk: clpk,
            sphincspk: pq_pk,

            ed25519sk: Some(cl),
            sphincssk: Some(pq_sk)
        }
    }
    pub fn sign<T: AsRef<[u8]>>(&self, data: T) -> Result<ShulginSignature,SlugErrors> {
        if self.ed25519sk.is_some() && self.sphincssk.is_some() {
            let cl_sig = self.ed25519sk.clone().unwrap().sign(data.as_ref());
            let pq_sig = self.sphincssk.clone().unwrap().sign(data.as_ref());

            if cl_sig.is_err() || pq_sig.is_err() {
                return Err(SlugErrors::SigningFailure(SlugErrorAlgorithms::SIG_SHULGINSIGNING))
            }
            else {
                Ok(
                    ShulginSignature {
                    clsig: cl_sig.unwrap(),
                    pqsig: pq_sig.unwrap(),
                    }
                )
            }



        }
        else {
            return Err(SlugErrors::SigningFailure(crate::errors::SlugErrorAlgorithms::SIG_SHULGINSIGNING))
        }
    }
    pub fn sign_message_with_csprng<T: AsRef<[u8]>>(&self, data: T) -> Result<(ShulginSignature,ShulginSignatureSigningInfo),SlugErrors> {
        let mut signing = ShulginSignatureSigningInfo::new();
        signing.message = Some(data.as_ref().to_vec());
        
        let output = serde_json::to_string(&signing).expect("Failed To Work");

        let x = self.sign(output)?;

        return Ok((x,signing))
    }
    pub fn sign_message_with_hedged_signatures<T: AsRef<[u8]>, S: AsRef<str>>(&self, data: T, pass: S) -> Result<(ShulginSignature,ShulginSignatureSigningInfo),SlugErrors> {
        let mut signing = ShulginSignatureSigningInfo::new_with_hedged_signatures(pass.as_ref());
        signing.message = Some(data.as_ref().to_vec());

        let output = serde_json::to_string(&signing).expect("Failed To Work");

        let x = self.sign(output)?;

        return Ok((x,signing))
    }
    pub fn verify<T: AsRef<[u8]>>(&self, data: T, signature: &ShulginSignature) -> Result<bool,SlugErrors> {
        let cl_is_valid = self.ed25519pk.verify(signature.clsig.clone(),data.as_ref());
        let pq_is_valid = self.sphincspk.verify(data.as_ref(), signature.pqsig.clone());

        if cl_is_valid.is_err() {
            return Err(SlugErrors::VerifyingError(crate::errors::SlugErrorAlgorithms::SIG_ED25519))
        }
        else if pq_is_valid.is_err() {
            return Err(SlugErrors::VerifyingError(crate::errors::SlugErrorAlgorithms::SIG_SPHINCS_PLUS))
        }
        else {
            if cl_is_valid.unwrap() == true && pq_is_valid.unwrap() == true {
                return Ok(true)
            }
            else {
                return Ok(false)
            }
        }
    }
    pub fn verify_with_signinginfo(&self, signatureinfo: &ShulginSignatureSigningInfo, signature: &ShulginSignature) -> Result<bool,SlugErrors> {
        let x = signatureinfo.serialize()?;
        let is_valid = self.verify(x,&signature)?;
        Ok(is_valid)
    }
    /// # From X59 Public Key Format
    /// 
    /// Public Key Only
    pub fn from_compact_pk<T: AsRef<str>>(pk: T) -> Result<ShulginKeypair, SlugErrors> {
        return from_public_key_compact(pk.as_ref())
    }
    /// # From X59 Public Key and Secret Key
    pub fn from_compact_keypair<T: AsRef<str>>(pk: T, sk: T) -> Result<ShulginKeypair, SlugErrors> {
        let mut x = from_public_key_compact(pk.as_ref())?;
        let z = from_secret_key_compact(sk.as_ref())?;
        x.add_secret(z.0,z.1);

        return Ok(x)
    }
    pub fn into_compact(&self) -> Result<ShulginKeypairCompact,FromUtf8Error> {
        if self.ed25519sk.is_some() && self.sphincssk.is_some() {
            let pk = key_to_compact(&self)?;
            let sk = secret_key_to_compact(&self)?;

            return Ok(ShulginKeypairCompact {
                public_key: pk,
                secret_key: Some(sk)
            })
        }
        else {
            let pk = key_to_compact(&self)?;
            return Ok(ShulginKeypairCompact {
                public_key: pk,
                secret_key: None,
            })
        }
    }
    pub fn into_secret_pem(&self) -> Result<String,FromUtf8Error> {
        let x = Pem::new("SHULGINSIGNING-SECRET-KEY",self.into_compact()?.to_str_sk()).to_string();
        return Ok(x)
    }
    pub fn into_pem(&self) -> Result<String,FromUtf8Error> {
        let x = Pem::new("SHULGINSIGNING-PUBLIC-KEY", self.into_compact()?.to_str_pk()).to_string();
        return Ok(x)
    }
}

impl ShulginSignature {
    pub fn new(ed25519: ED25519Signature, sphincs: SPHINCSSignature) -> Self {
        return Self {
            clsig: ed25519,
            pqsig: sphincs,
        }
    }
    pub fn import(signature_compact: ShulginSignatureCompact) {
        return 
    }
    /// TODO: Refactor to use slugencode
    pub fn into_x59_format(&self) -> String {
        let mut output: String = String::new();
        
        let delimiter = ":";

        let upper_ed25519_sig = self.clsig.to_hex_string();
        let sphincs_sig_bs58 = self.pqsig.to_base58_string();

        output.push_str(&upper_ed25519_sig);
        output.push_str(delimiter);
        output.push_str(&sphincs_sig_bs58);

        return output
    }
    /// TODO: Refactor to use slugencode
    pub fn from_x59_format<T: AsRef<str>>(ss_format: T) -> Result<Self,SlugErrors> {
        let manipulated_string = ss_format.as_ref().to_string();

        let keys: Vec<&str> = manipulated_string.split(":").collect();

        if keys.len() != 2 {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }

        let output_ed = ED25519Signature::from_hex_string(keys[0]);
        let output_sphincs = SPHINCSSignature::from_base58_string(keys[1]);

        if output_ed.is_err() {
            return Err(SlugErrors::VerifyingError(SlugErrorAlgorithms::SIG_ED25519))
        } 
        else if output_sphincs.is_err() {
            return Err(SlugErrors::VerifyingError(SlugErrorAlgorithms::SIG_SPHINCS_PLUS))
        }
        else {
            let output_sig_cl: ED25519Signature = ED25519Signature::from_bytes(&output_ed.unwrap())?;
            let output_sig_pq: SPHINCSSignature = SPHINCSSignature::from_bytes(&output_sphincs.unwrap())?;

            return Ok(Self {
                clsig: output_sig_cl,
                pqsig: output_sig_pq,
        })
        }




    }
}

/// Naive Version Of ShulginSigning Compact Signature Verification
fn verify_signature_compact<T: AsRef<str>>(s: T) -> Result<bool,SlugErrors> {
    let manipulated_string = s.as_ref().to_string();

    let colon_count = manipulated_string.chars().filter(|c| *c == ':').count();

    if manipulated_string.contains(":") == true && colon_count == 1 {
        {
            let x: Vec<&str> = manipulated_string.split(":").collect();
            if x[0].len() != 128 {
                return Err(SlugErrors::Other(String::from("ED25519 Hexadecimal not equal to 128 chars.")))
            }
            else {
                return Ok(true)
            }
        }
    }
    else {
        return Err(SlugErrors::Other(String::from("Does Not Contain Colon Or Contains Too Many Colons")))
    }
}

fn key_to_compact(keypair: &ShulginKeypair) -> Result<String, FromUtf8Error> {
    let mut output: String = String::new();
    
    let delimiter = ":";
    
    let ed25519_pk = &keypair.ed25519pk;
    let sphincs_pk = &keypair.sphincspk;

    output.push_str(&ed25519_pk.to_hex_string());
    output.push_str(delimiter);
    output.push_str(&sphincs_pk.to_hex_string()?);

    return Ok(output)
}

fn from_public_key_compact<T: AsRef<str>>(ss_pk: T) -> Result<ShulginKeypair,SlugErrors> {
    let x = ss_pk.as_ref().to_string();

    let keys: Vec<&str> = x.split(":").collect();

    let hex_str = ED25519PublicKey::from_hex_string(keys[0]).unwrap();

    let mut byte_array: [u8;32] = [0u8;32];

    if hex_str.len() == 32 {
        byte_array.copy_from_slice(&hex_str)
    }

    if keys.len() == 2 {
        if keys[0].len() == 64 && keys[1].len() == 128 {
            return Ok(ShulginKeypair {
                ed25519pk: ED25519PublicKey::from_bytes(byte_array),
                sphincspk: SPHINCSPublicKey::from_hex_string_final(keys[1])?,

                sphincssk: None,
                ed25519sk: None,
            })
        }
        else {
            return Err(SlugErrors::Other(String::from("Error when compacting key for shulgin signing.")))
        }
    }
    else {
        return Err(SlugErrors::Other(String::from("Key Length Too High")))
    }

}

fn from_secret_key_compact<T: AsRef<str>>(ss_sk: T) -> Result<(ED25519SecretKey,SPHINCSSecretKey), SlugErrors> {
    let x = ss_sk.as_ref().to_string();

    let keys: Vec<&str> = x.split(":").collect();

    let hex_str = ED25519SecretKey::from_hex_string(keys[0]).unwrap();

    let mut byte_array: [u8;32] = [0u8;32];

    if hex_str.len() == 32 {
        byte_array.copy_from_slice(&hex_str)
    }

    if keys.len() == 2 {
        if keys[0].len() == 64 && keys[1].len() == 256 {
            return Ok((ED25519SecretKey::from_bytes(&byte_array).unwrap(),SPHINCSSecretKey::from_bytes(&SPHINCSSecretKey::from_hex_string(keys[1]).unwrap()).unwrap()))
        }
        else {
            return Err(SlugErrors::Other(String::from("Failed To Convert")))
        }
    }
    else {
        return Err(SlugErrors::Other(String::from("Failed To Convert")))
    }
}

fn secret_key_to_compact(keypair: &ShulginKeypair) -> Result<String, FromUtf8Error> {
    let mut output: String = String::new();
    
    let delimiter = ":";
    
    let ed25519_sk = keypair.ed25519sk.clone().unwrap();
    let sphincs_sk = keypair.sphincssk.clone().unwrap();

    output.push_str(&ed25519_sk.to_hex_string());
    output.push_str(delimiter);
    output.push_str(&sphincs_sk.to_hex_string()?);

    return Ok(output)
}

fn remove_first(s: &str) -> Option<&str> {
    s.chars().next().map(|c| &s[c.len_utf8()..])
}

impl IntoStandardPem for ShulginKeypair {
    fn into_standard_pem(&self) -> Result<String,SlugErrors> {
        if self.sphincssk.is_some() && self.ed25519sk.is_some() {
            let key = self.into_bincode()?;
            let pem = Pem::new(Self::label_for_standard_pem_secret(), key);
            return Ok(pem.to_string())
        }
        else if self.sphincssk.is_none() && self.ed25519sk.is_none() {
            let key = self.into_bincode()?;
            let pem = Pem::new(Self::label_for_standard_pem(), key);
            return Ok(pem.to_string())
        }
        else {
            return Err(SlugErrors::Other(String::from("Cannot Convert To PEM. Both Secret Keys Must Be Present Or Both Secret Keys Must Be Absent.")))
        }
    }
    fn label_for_standard_pem() -> String {
        String::from("OpenInternetCryptographyProject/ShulginSigning-Public-Key")
    }
    fn label_for_standard_pem_secret() -> String {
        String::from("OpenInternetCryptographyProject/ShulginSigning-Secret-Key")
    }
}

impl IntoStandardPem for ShulginSignature {
    fn into_standard_pem(&self) -> Result<String, SlugErrors> {
        let key = self.into_bincode()?;
        let pem = Pem::new(String::from(Self::label_for_standard_pem()), key);
        return Ok(pem.to_string())
    }
    fn label_for_standard_pem() -> String {
        String::from("OpenInternetCryptographyProject/ShulginSigning-Signature")
    }
    fn label_for_standard_pem_secret() -> String {
        String::from("OpenInternetCryptographyProject/ShulginSigning-Secret-Key")
    }
}

impl FromStandardPem for ShulginKeypair {
    fn from_standard_pem<T: AsRef<str>>(pem_str: T) -> Result<Self, SlugErrors> {
        let pem = Pem::from_str(pem_str.as_ref())?;

        if pem.tag() == Self::label_for_standard_pem() || pem.tag() == Self::label_for_standard_pem_secret() {
            let key = pem.contents();
            let keypair = Self::from_bincode(key)?;
            return Ok(keypair)
        }
        else {
            return Err(SlugErrors::Other(String::from("PEM Label Does Not Match Expected Label For ShulginSigning Keypair.")))
        }
    }
}

impl FromStandardPem for ShulginSignature {
    fn from_standard_pem<T: AsRef<str>>(pem_str: T) -> Result<Self, SlugErrors> {
        let pem = Pem::from_str(pem_str.as_ref())?;

        if pem.tag() == Self::label_for_standard_pem() {
            let key = pem.contents();
            let signature = Self::from_bincode(key)?;
            return Ok(signature)
        }
        else {
            return Err(SlugErrors::Other(String::from("PEM Label Does Not Match Expected Label For ShulginSigning Signature.")))
        }
    }
}

#[test]
fn run() {
    let keypair = ShulginKeypair::generate();
    let signature = keypair.sign("This message is being signed.").unwrap();


    let sig = signature.into_x59_format();

    let compact = ShulginKeypairCompact::from_pk(&keypair).unwrap();
    
    println!("{}",compact.as_str_pk())
}



#[test]
fn shulginsigning() {
    let keypair = ShulginKeypair::generate();
    let signature = keypair.sign("Data").unwrap();
    let compact = keypair.into_compact().unwrap();
    let pk_str = compact.as_str_pk();
    let sk_str = compact.to_str_sk();

    let pem = keypair.into_pem().unwrap();

    println!("PEM: {}", pem);

    println!("Public Key: {}",pk_str);
    println!("Secret Key: {}",sk_str.clone());

    let keypair2 = ShulginKeypair::from_compact_keypair(pk_str, &sk_str).unwrap();

    let is_valid = keypair2.verify("Data", &signature).unwrap();

    println!("Is Valid: {}", is_valid);
}

#[test]
fn check_len() {
    let keypair = ShulginKeypair::generate();
    let msg: &str = "Message that is signed";
    let signature = keypair.sign(msg).unwrap();
    let format = keypair.to_x59_pk_format();
    let keypair2 = ShulginKeypair::from_x59_pk_format(format.unwrap()).unwrap();
    let output = keypair.to_x59_format_full().unwrap();
    let keypair_2 = ShulginKeypair::from_x59_format_full(output).unwrap();
    let is_valid = keypair_2.verify(msg, &signature).unwrap();
    println!("{}",is_valid);

}

impl IntoBincode for ShulginKeypair {
    fn into_bincode(&self) -> Result<Vec<u8>, SlugErrors> {
        Ok(bincode::serialize(&self)?)
    }
}

impl IntoBincode for ShulginSignature {
    fn into_bincode(&self) -> Result<Vec<u8>, SlugErrors> {
        Ok(bincode::serialize(&self)?)
    }
}

impl FromBincode for ShulginKeypair {
    fn from_bincode<T: AsRef<[u8]>>(bincode_encoded: T) -> Result<Self, SlugErrors> {
        Ok(bincode::deserialize(bincode_encoded.as_ref())?)
    }
}

impl FromBincode for ShulginSignature {
    fn from_bincode<T: AsRef<[u8]>>(bincode_encoded: T) -> Result<Self, SlugErrors> {
        Ok(bincode::deserialize(bincode_encoded.as_ref())?)
    }
}
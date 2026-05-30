//! # MLDSA87: ML-DSA Level 5 Security As Standardized In FIPS 204
//! 
//! ### Algorithm
//! 
//! **Post-Quantum:** True
//! 
//! **Security-Level:** Level 5
//! 
//! **Standard:** FIPS 204
//! 
//! **Algorithm:** ML-DSA87 (Dilithium87)
//! 
//! ### Key Size
//! 
//! **Public Key Size:** 2592-bytes
//! 
//! **Secret Key Size:** 4896-bytes or 32-byte seed
//! 
//! **Signature Size:** 4627-bytes
//! 
//! ### Implemented Traits
//! 
//! - [X] Bincode
//!     - [X] FromBincode
//!     - [X] IntoBincode
//! - [X] Encoding
//!     - [X] FromEncoding
//!     - [X] IntoEncoding
//! - [X] StandardPem
//!     - [X] Into
//!     - [X] From
use std::str::FromStr;

use ml_dsa_new::EncodedSignature;
use ml_dsa_new::MlDsa87;
use ml_dsa_new::Generate;
use ml_dsa_new::Keypair;
use ml_dsa_new::KeySizeUser;
use ml_dsa_new::KeyInit;
use ml_dsa_new::KeyExport;
use ml_dsa_new::MlDsaParams;
use ml_dsa_new::SignatureEncoding;
use ml_dsa_new::Signer;
use ml_dsa_new::Verifier;
use ml_dsa_new::{SigningKey,VerifyingKey,Signature};
use pem::Pem;
use rand_2::CryptoRng;
use securerand_rs::bip39::SlugBIP39Languages;
use securerand_rs::bip39::SlugBIP39Words;
use securerand_rs::bip39::SlugMnemonic;
use serde::{Serialize,Deserialize};
use serde_big_array::BigArray;
use slugencode::SlugEncodingUsage;
use slugencode::SlugEncodings;
use zeroize::{Zeroize,ZeroizeOnDrop};
use crate::errors::SlugErrorAlgorithms;
use crate::errors::SlugErrors;
use hybird_array_four::{Array,ArrayN,ArraySize};

// =TRAITS IMPLEMENTED=
use crate::slugcrypt::traits::{IntoEncoding,FromEncoding};
use crate::slugcrypt::traits::{FromBincode,IntoBincode};
use crate::slugcrypt::traits::{FromStandardPem, IntoStandardPem};
// =END OF TRAITS IMPLEMENTED=

//use crate::slugcrypt::traits::{IntoX59PublicKey,IntoX59SecretKey,IntoX59Signature};
//use crate::slugcrypt::traits::{IntoStandardEncoding,FromStandardEncoding};

pub const DEFAULT_CONTEXT: &str = "OpenInternetCryptographyProject";

pub mod info {
    /// # MLDSA-87 Cipher Suite
    /// 
    /// This is the cipher suite for MLDSA-87.
    /// 
    /// The cipher suite is "OpenInternetCryptographyProject/Standardized/ML-DSA87".
    pub const CIPHER_SUITE: &str = "OpenInternetCryptographyProject/Standardized/ML-DSA87";

    pub const NAME: &str = "MLDSA87";
    pub const ALGORITHM: &str = "MLDSA87";
    pub const CONTEXT: &str = "OpenInternetCryptographyProject";
    pub const SECRET_SEED_SIZE_IN_BYTES: usize = 32;
    /// 4896
    pub const SECRET_KEY_SIZE_IN_BYTES: usize = 4_896;
    /// 2592
    pub const PUBLIC_KEY_SIZE_IN_BYTES: usize = 2_592;
    /// 4627
    pub const SIGNATURE_SIZE_IN_BYTES: usize = 4_627;
}

/// # MLDSA-87 Secret Key Seed
/// 
/// This is used to derive the secret key and public key using the seed. This is equivalent to the secret key as it is just a seed to be derived from.
/// 
/// The seed is 32-bytes in length.
#[derive(Serialize,Deserialize,Clone,Debug,PartialEq, Hash, Zeroize, ZeroizeOnDrop, PartialOrd)]
pub struct MLDSA87SecretSeed {
    pub seed: [u8; 32]
}

#[derive(Serialize,Deserialize,Clone,Debug,PartialEq, Hash, Zeroize, ZeroizeOnDrop, PartialOrd)]
pub struct MLDSA87PublicKey {
    #[serde(with = "BigArray")]
    pub pk: [u8; 2_592]
}

#[derive(Serialize,Deserialize,Clone,Debug,PartialEq, Hash, Zeroize, ZeroizeOnDrop, PartialOrd)]
pub struct MLDSA87SecretKey {
    #[serde(with = "BigArray")]
    pub sk: [u8;4_896]
}

#[derive(Serialize,Deserialize,Clone,Debug,PartialEq, Hash, Zeroize, ZeroizeOnDrop, PartialOrd)]
pub struct MLDSA87Signature {
    #[serde(with = "BigArray")]
    pub sig: [u8; 4_627]
}

impl MLDSA87SecretSeed {
    /// # New MLDSA-87 Secret Key Seed
    /// 
    /// Create a new MLDSA-87 Secret Key Seed from a 32-byte seed
    pub fn new(seed: [u8; 32]) -> MLDSA87SecretSeed {
        MLDSA87SecretSeed { seed: seed }
    }
    /// # From Bytes MLDSA-87 Secret Key Seed
    /// 
    /// Create a new MLDSA-87 Secret Key Seed from a byte array
    pub fn from_bytes(seed: &[u8]) -> Result<Self,SlugErrors> {
        if seed.len() != 32 {
            Err(SlugErrors::Unknown)
        }
        else {
            return Ok(MLDSA87SecretSeed { seed: seed.try_into().unwrap() })
        }
    }
    /// # To Bytes MLDSA-87 Secret Key Seed
    /// 
    /// Get the byte array representation of the MLDSA-87 Secret Key Seed
    pub fn to_bytes(&self) -> [u8; 32] {
        return self.seed
    }
    /// # To Vec MLDSA-87 Secret Key Seed
    /// 
    /// Get the vector representation of the MLDSA-87 Secret Key Seed
    pub fn to_vec(&self) -> Vec<u8> {
        return self.seed.to_vec()
    }
    /// # Into Secret Key Usable Type
    /// 
    /// Get the MLDSA-87 Secret Key from the MLDSA-87 Secret Key Seed
    pub fn into_secret_key_usable_type(&self) -> SigningKey<MlDsa87> {
        return SigningKey::<MlDsa87>::from_seed(&self.seed.into());
    }
    /// # Into Public Key Usable Type
    /// 
    /// Get the MLDSA-87 Public Key from the MLDSA-87 Secret Key
    pub fn into_public_key_usable_type(&self) -> VerifyingKey<MlDsa87> {
        let output: VerifyingKey<MlDsa87> = self.into_secret_key_usable_type().verifying_key();
        return output
    }
    /// # Into Public Key From Seed
    /// 
    /// Get the MLDSA-87 Public Key from the MLDSA-87 Seed
    /// 
    /// **Public Key Length:** 2,592 bytes
    pub fn into_public_key(&self) -> MLDSA87PublicKey {
        let output: VerifyingKey<MlDsa87> = self.into_secret_key_usable_type().verifying_key();
        let bytes = output.to_bytes();
        let mut pk_array = [0u8; 2_592];
        pk_array.copy_from_slice(&bytes[0..2_592]);
        return MLDSA87PublicKey::from_bytes(&pk_array).unwrap()
    }
    pub fn sign<T: AsRef<[u8]>>(&self, message: T) -> Result<MLDSA87Signature,SlugErrors> {
        let signature = self.into_secret_key_usable_type().try_sign(message.as_ref());

        if signature.is_ok() {
            let x = &signature.unwrap();
            let bytes = x.to_bytes();
            return Ok(MLDSA87Signature::from_bytes(&bytes).unwrap())
        }
        else {
            return Err(SlugErrors::SigningFailure(crate::errors::SlugErrorAlgorithms::SIG_MLDSA))
        }
    }
}


impl MLDSA87PublicKey {
    /// # From Bytes MLDSA-87 Public Key
    /// 
    /// Create a new MLDSA-87 Public Key from a byte array
    pub fn from_bytes(pk: &[u8]) -> Result<Self,SlugErrors> {
        if pk.len() != 2_592 {
            Err(SlugErrors::Unknown)
        }
        else {
            return Ok(MLDSA87PublicKey { pk: pk.try_into().unwrap() })
        }
    }
    /// # To Bytes MLDSA-87 Public Key
    /// 
    /// Get the byte array representation of the MLDSA-87 Public Key
    pub fn to_bytes(&self) -> [u8; 2_592] {
        return self.pk
    }
    /// # To Vec MLDSA-87 Public Key
    /// 
    /// Get the vector representation of the MLDSA-87 Public Key
    pub fn to_vec(&self) -> Vec<u8> {
        return self.pk.to_vec()
    }
    pub fn into_verifying_key_usable_type(&self) -> Result<VerifyingKey<MlDsa87>,SlugErrors> {
        let key = self.to_bytes();
        let usable = VerifyingKey::new_from_slice(&key);

        if usable.is_err() {
            return Err(SlugErrors::Unknown);
        }
        else {
            return Ok(usable.unwrap())
        }
    }
    pub fn verify<T:AsRef<[u8]>>(&self, message: T, signature: &MLDSA87Signature) -> Result<bool,SlugErrors> {
        let vk: VerifyingKey<MlDsa87> = self.into_verifying_key_usable_type()?;
        let sig: Signature<MlDsa87> = signature.to_usable_type()?;
        let output: Result<(), _> = vk.verify(message.as_ref(), &sig);

        if output.is_ok() {
            return Ok(true)
        }
        else {
            return Ok(false)
        }
    }
}

impl MLDSA87Signature {
    pub fn from_bytes(sig: &[u8]) -> Result<Self,SlugErrors> {
        if sig.len() != 4627 {
            Err(SlugErrors::Unknown)
        }
        else {
            return Ok(MLDSA87Signature { sig: sig.try_into().unwrap() })
        }
    }
    pub fn from_array(sig: [u8; 4627]) -> MLDSA87Signature {
        return MLDSA87Signature { sig: sig }
    }
    pub fn verify(&self, message: &[u8], pk: &MLDSA87PublicKey) -> Result<bool,SlugErrors> {
        let key = pk.into_verifying_key_usable_type()?;
        let output = key.verify(message, &self.to_usable_type()?);
        if output.is_ok() {
            return Ok(true)
        }
        else {
            return Ok(false)
        }
    }
    pub fn to_usable_type(&self) -> Result<Signature<MlDsa87>,SlugErrors> {
        let output = *Array::from_slice(&self.sig);
        
        let sig = Signature::decode(output.as_ref());

        if sig.is_some() {
            return Ok(sig.unwrap())
        }
        else {
            return Err(SlugErrors::Unknown)
        }
    }
}
pub struct GenerateMLDSA87;

impl GenerateMLDSA87 {
    /// Generate a new ML-DSA87 key using randomness
    pub fn generate() {
        let key: SigningKey<MlDsa87> = SigningKey::<MlDsa87>::generate();
    }
    /// Generate a new ML-DSA87 key using the cryptorng trait.
    pub fn generate_from_rng<R: CryptoRng + ?Sized>(mut rng: &mut R) {
        let key: SigningKey<MlDsa87> = SigningKey::<MlDsa87>::generate_from_rng(&mut rng);
    }
    pub fn generate_using_bip39(mnemonic: SlugMnemonic, password: &str) -> Result<MLDSA87SecretSeed,SlugErrors> {
        let x: Result<securerand_rs::bip39::MnemnonicSeed, bip39::ErrorKind> = mnemonic.to_seed_with_crypto(password);

        if x.is_ok() {
            let mut seed = x.unwrap();
            let key = SigningKey::<MlDsa87>::generate_from_rng(&mut seed);
            let seed = key.to_seed();
            let seed_slice = seed.as_slice();
            let output_seed = MLDSA87SecretSeed::from_bytes(seed_slice)?;
            Ok(output_seed)
        }
        else {
            Err(SlugErrors::Unknown)
        }
    }
    /// # Generate With BIP39
    pub fn generate_with_bip39(number_of_words: SlugBIP39Words, language: SlugBIP39Languages, pass: &str) -> Result<(SlugMnemonic, MLDSA87SecretSeed),SlugErrors> {
        let x: SlugMnemonic = SlugMnemonic::new(number_of_words, language);
        let seed: MLDSA87SecretSeed = GenerateMLDSA87::generate_using_bip39(x.clone(), pass)?;
        Ok((x.clone(), seed))
    }
    pub fn generate_with_bip39_no_password(number_of_words: SlugBIP39Words, language: SlugBIP39Languages) -> Result<(SlugMnemonic, MLDSA87SecretSeed),SlugErrors> {
        return Self::generate_with_bip39(number_of_words, language, "");
    }
    /// # Generate With BIP39 (Default Password)
    /// 
    /// Password: "OpenInternetCryptographyProject"
    pub fn generate_with_bip39_with_default_slug_password(number_of_words: SlugBIP39Words, language: SlugBIP39Languages) -> Result<(SlugMnemonic, MLDSA87SecretSeed),SlugErrors> {
        return Self::generate_with_bip39(number_of_words, language, DEFAULT_CONTEXT)
    }
}

impl MLDSA87SecretKey {
    pub fn from_bytes(key: &[u8]) -> Result<Self,SlugErrors> {
        if key.len() != 4896 {
            Err(SlugErrors::Unknown)
        }
        else {
            let mut output: [u8; 4896] = [0; 4896];
            output.copy_from_slice(key);
            return Ok(MLDSA87SecretKey { sk: output })
        }
    }
    pub fn to_bytes(&self) -> [u8; 4896] {
        return self.sk
    }
    pub fn as_bytes(&self) -> &[u8] {
        return &self.sk
    }
    pub fn to_vec(&self) -> Vec<u8> {
        return self.sk.to_vec()
    }
}

//=====BINCODE=====//

impl IntoBincode for MLDSA87PublicKey {
    fn into_bincode(&self) -> Result<Vec<u8>,SlugErrors> {
        let output = bincode::serialize(&self);

        if output.is_err() {
            return Err(SlugErrors::BincodeError{ alg: SlugErrorAlgorithms::STD_MLDSA87 })
        }
        else {
            return Ok(output.unwrap())
        }
    }
}

impl IntoBincode for MLDSA87SecretSeed {
    fn into_bincode(&self) -> Result<Vec<u8>,SlugErrors> {
        let output = bincode::serialize(&self);

        if output.is_err() {
            return Err(SlugErrors::BincodeError{ alg: SlugErrorAlgorithms::STD_MLDSA87 })
        }
        else {
            return Ok(output.unwrap())
        }
    }
}

impl IntoBincode for MLDSA87Signature {
    fn into_bincode(&self) -> Result<Vec<u8>,SlugErrors> {
        let output = bincode::serialize(&self);

        if output.is_err() {
            return Err(SlugErrors::BincodeError{ alg: SlugErrorAlgorithms::STD_MLDSA87 })
        }
        else {
            return Ok(output.unwrap())
        }
    }
}

impl IntoBincode for MLDSA87SecretKey {
    fn into_bincode(&self) -> Result<Vec<u8>,SlugErrors> {
        let output = bincode::serialize(&self);

        if output.is_err() {
            return Err(SlugErrors::BincodeError{ alg: SlugErrorAlgorithms::STD_MLDSA87 })
        }
        else {
            return Ok(output.unwrap())
        }
    }
}

impl FromBincode for MLDSA87SecretKey {
    fn from_bincode<T: AsRef<[u8]>>(bytes: T) -> Result<Self,SlugErrors> {
        let output: Result<MLDSA87SecretKey, Box<bincode::ErrorKind>> = bincode::deserialize(bytes.as_ref());

        if output.is_err() {
            return Err(SlugErrors::BincodeError{ alg: SlugErrorAlgorithms::STD_MLDSA87 })
        }
        else {
            return Ok(output.unwrap())
        }
    }
}

impl FromBincode for MLDSA87PublicKey {
    fn from_bincode<T: AsRef<[u8]>>(bytes: T) -> Result<Self,SlugErrors> {
        let output: Result<MLDSA87PublicKey, Box<bincode::ErrorKind>> = bincode::deserialize(bytes.as_ref());

        if output.is_err() {
            return Err(SlugErrors::BincodeError{ alg: SlugErrorAlgorithms::STD_MLDSA87 })
        }
        else {
            return Ok(output.unwrap())
        }
    }
}

impl FromBincode for MLDSA87Signature {
    fn from_bincode<T: AsRef<[u8]>>(bytes: T) -> Result<Self,SlugErrors> {
        let output: Result<MLDSA87Signature, Box<bincode::ErrorKind>> = bincode::deserialize(bytes.as_ref());

        if output.is_err() {
            return Err(SlugErrors::BincodeError{ alg: SlugErrorAlgorithms::STD_MLDSA87 })
        }
        else {
            return Ok(output.unwrap())
        }
    }
}

impl FromBincode for MLDSA87SecretSeed {
    fn from_bincode<T: AsRef<[u8]>>(bytes: T) -> Result<Self,SlugErrors> {
        let output: Result<MLDSA87SecretSeed, Box<bincode::ErrorKind>> = bincode::deserialize(bytes.as_ref());

        if output.is_err() {
            return Err(SlugErrors::BincodeError{ alg: SlugErrorAlgorithms::STD_MLDSA87 })
        }
        else {
            return Ok(output.unwrap())
        }
    }
}

//=====END BINCODE=====//

//=====ENCODINGS=====//
impl IntoEncoding for MLDSA87PublicKey {
    fn into_hex(&self) -> Result<String,SlugErrors> {
        let encoder = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output: String = encoder.encode(&self.pk)?;
        Ok(output)
    }
    fn into_base32(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Base32).encode(&self.pk)?; 
        Ok(output)
    }
    fn into_base32_unpadded(&self) -> Result<String,SlugErrors> {
        let output = SlugEncodingUsage::new(SlugEncodings::Base32unpadded).encode(&self.pk)?; 
        Ok(output)
    }
    fn into_base58(&self) -> Result<String,SlugErrors> {
        let output = SlugEncodingUsage::new(SlugEncodings::Base58).encode(&self.pk)?; 
        Ok(output)
    }
    fn into_base64(&self) -> Result<String,SlugErrors> {
        let output = SlugEncodingUsage::new(SlugEncodings::Base64).encode(&self.pk)?; 
        Ok(output)
    }
    fn into_base64_url_safe(&self) -> Result<String,SlugErrors> {
        let output = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe).encode(&self.pk)?; 
        Ok(output)
    }
}

impl IntoEncoding for MLDSA87Signature {
    fn into_hex(&self) -> Result<String,SlugErrors> {
        let encoder = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output: String = encoder.encode(&self.sig)?; 
        Ok(output)
    }
    fn into_base32(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Base32).encode(&self.sig)?; 
        Ok(output)
    }
    fn into_base32_unpadded(&self) -> Result<String,SlugErrors> {
        let output = SlugEncodingUsage::new(SlugEncodings::Base32unpadded).encode(&self.sig)?; 
        Ok(output)
    }
    fn into_base58(&self) -> Result<String,SlugErrors> {
        let output = SlugEncodingUsage::new(SlugEncodings::Base58).encode(&self.sig)?; 
        Ok(output)
    }
    fn into_base64(&self) -> Result<String,SlugErrors> {
        let output = SlugEncodingUsage::new(SlugEncodings::Base64).encode(&self.sig)?; 
        Ok(output)
    }
    fn into_base64_url_safe(&self) -> Result<String,SlugErrors> {
        let output = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe).encode(&self.sig)?; 
        Ok(output)
    }
}

impl IntoEncoding for MLDSA87SecretKey {
    fn into_hex(&self) -> Result<String,SlugErrors> {
        let encoder = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output: String = encoder.encode(&self.sk)?; 
        Ok(output)
    }
    fn into_base32(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Base32).encode(&self.sk)?; 
        Ok(output)
    }
    fn into_base32_unpadded(&self) -> Result<String,SlugErrors> {
        let output = SlugEncodingUsage::new(SlugEncodings::Base32unpadded).encode(&self.sk)?; 
        Ok(output)
    }
    fn into_base58(&self) -> Result<String,SlugErrors> {
        let output = SlugEncodingUsage::new(SlugEncodings::Base58).encode(&self.sk)?; 
        Ok(output)
    }
    fn into_base64(&self) -> Result<String,SlugErrors> {
        let output = SlugEncodingUsage::new(SlugEncodings::Base64).encode(&self.sk)?;
        Ok(output)
    }
    fn into_base64_url_safe(&self) -> Result<String,SlugErrors> {
        let output = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe).encode(&self.sk)?; 
        Ok(output)
    }
}

impl IntoEncoding for MLDSA87SecretSeed {
    fn into_hex(&self) -> Result<String,SlugErrors> {
        let encoder = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output: String = encoder.encode(&self.seed)?; 
        Ok(output)
    }
    fn into_base32(&self) -> Result<String,SlugErrors> {
        let output: String = SlugEncodingUsage::new(SlugEncodings::Base32).encode(&self.seed)?; 
        Ok(output)
    }
    fn into_base32_unpadded(&self) -> Result<String,SlugErrors> {
        let output = SlugEncodingUsage::new(SlugEncodings::Base32unpadded).encode(&self.seed)?; 
        Ok(output)
    }
    fn into_base58(&self) -> Result<String,SlugErrors> {
        let output = SlugEncodingUsage::new(SlugEncodings::Base58).encode(&self.seed)?; 
        Ok(output)
    }
    fn into_base64(&self) -> Result<String,SlugErrors> {
        let output = SlugEncodingUsage::new(SlugEncodings::Base64).encode(&self.seed)?; 
        Ok(output)
    }
    fn into_base64_url_safe(&self) -> Result<String,SlugErrors> {
        let output = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe).encode(&self.seed)?; 
        Ok(output)
    }
}

impl FromEncoding for MLDSA87PublicKey {
    fn from_hex<T: AsRef<str>>(input: T) -> Result<MLDSA87PublicKey,SlugErrors> {
        let input = SlugEncodingUsage::new(SlugEncodings::Hex).decode(input)?; 
        Ok(MLDSA87PublicKey::from_bytes(&input)?)
    }
    fn from_base32<T: AsRef<str>>(input: T) -> Result<MLDSA87PublicKey,SlugErrors> {
        let input = SlugEncodingUsage::new(SlugEncodings::Base32).decode(input)?; 
        Ok(MLDSA87PublicKey::from_bytes(&input)?)
    }
    fn from_base32_unpadded<T: AsRef<str>>(input: T) -> Result<MLDSA87PublicKey,SlugErrors> {
        let input = SlugEncodingUsage::new(SlugEncodings::Base32unpadded).decode(input)?; 
        Ok(MLDSA87PublicKey::from_bytes(&input)?)
    }
    fn from_base58<T: AsRef<str>>(input: T) -> Result<MLDSA87PublicKey,SlugErrors> {
        let input = SlugEncodingUsage::new(SlugEncodings::Base58).decode(input)?; 
        Ok(MLDSA87PublicKey::from_bytes(&input)?)
    }
    fn from_base64<T: AsRef<str>>(input: T) -> Result<MLDSA87PublicKey,SlugErrors> {
        let input = SlugEncodingUsage::new(SlugEncodings::Base64).decode(input)?; 
        Ok(MLDSA87PublicKey::from_bytes(&input)?)
    }
    fn from_base64_url_safe<T: AsRef<str>>(input: T) -> Result<MLDSA87PublicKey,SlugErrors> {
        let input = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe).decode(input)?; 
        Ok(MLDSA87PublicKey::from_bytes(&input)?)
    }
}

impl FromEncoding for MLDSA87SecretKey {
    fn from_hex<T: AsRef<str>>(input: T) -> Result<MLDSA87SecretKey,SlugErrors> {
        let input = SlugEncodingUsage::new(SlugEncodings::Hex).decode(input)?; 
        Ok(MLDSA87SecretKey::from_bytes(&input)?)
    }
    fn from_base32<T: AsRef<str>>(input: T) -> Result<MLDSA87SecretKey,SlugErrors> {
        let input = SlugEncodingUsage::new(SlugEncodings::Base32).decode(input)?; 
        Ok(MLDSA87SecretKey::from_bytes(&input)?)
    }
    fn from_base32_unpadded<T: AsRef<str>>(input: T) -> Result<MLDSA87SecretKey,SlugErrors> {
        let input = SlugEncodingUsage::new(SlugEncodings::Base32unpadded).decode(input)?; 
        Ok(MLDSA87SecretKey::from_bytes(&input)?)
    }
    fn from_base58<T: AsRef<str>>(input: T) -> Result<MLDSA87SecretKey,SlugErrors> {
        let input = SlugEncodingUsage::new(SlugEncodings::Base58).decode(input)?; 
        Ok(MLDSA87SecretKey::from_bytes(&input)?)
    }
    fn from_base64<T: AsRef<str>>(input: T) -> Result<MLDSA87SecretKey,SlugErrors> {
        let input = SlugEncodingUsage::new(SlugEncodings::Base64).decode(input)?; 
        Ok(MLDSA87SecretKey::from_bytes(&input)?)
    }
    fn from_base64_url_safe<T: AsRef<str>>(input: T) -> Result<MLDSA87SecretKey,SlugErrors> {
        let input = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe).decode(input)?; 
        Ok(MLDSA87SecretKey::from_bytes(&input)?)
    }
}

impl FromEncoding for MLDSA87Signature {
    fn from_hex<T: AsRef<str>>(input: T) -> Result<MLDSA87Signature,SlugErrors> {
        let input = SlugEncodingUsage::new(SlugEncodings::Hex).decode(input)?; 
        Ok(MLDSA87Signature::from_bytes(&input)?)
    }
    fn from_base32<T: AsRef<str>>(input: T) -> Result<MLDSA87Signature,SlugErrors> {
        let input = SlugEncodingUsage::new(SlugEncodings::Base32).decode(input)?; 
        Ok(MLDSA87Signature::from_bytes(&input)?)
    }
    fn from_base32_unpadded<T: AsRef<str>>(input: T) -> Result<MLDSA87Signature,SlugErrors> {
        let input = SlugEncodingUsage::new(SlugEncodings::Base32unpadded).decode(input)?; 
        Ok(MLDSA87Signature::from_bytes(&input)?)
    }
    fn from_base58<T: AsRef<str>>(input: T) -> Result<MLDSA87Signature,SlugErrors> {
        let input = SlugEncodingUsage::new(SlugEncodings::Base58).decode(input)?; 
        Ok(MLDSA87Signature::from_bytes(&input)?)
    }
    fn from_base64<T: AsRef<str>>(input: T) -> Result<MLDSA87Signature,SlugErrors> {
        let input = SlugEncodingUsage::new(SlugEncodings::Base64).decode(input)?; 
        Ok(MLDSA87Signature::from_bytes(&input)?)
    }
    fn from_base64_url_safe<T: AsRef<str>>(input: T) -> Result<MLDSA87Signature,SlugErrors> {
        let input = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe).decode(input)?; 
        Ok(MLDSA87Signature::from_bytes(&input)?)
    }
}

impl FromEncoding for MLDSA87SecretSeed {
    fn from_hex<T: AsRef<str>>(input: T) -> Result<MLDSA87SecretSeed,SlugErrors> {
        let input = SlugEncodingUsage::new(SlugEncodings::Hex).decode(input)?; 
        Ok(MLDSA87SecretSeed::from_bytes(&input)?)
    }
    fn from_base32<T: AsRef<str>>(input: T) -> Result<MLDSA87SecretSeed,SlugErrors> {
        let input = SlugEncodingUsage::new(SlugEncodings::Base32).decode(input)?; 
        Ok(MLDSA87SecretSeed::from_bytes(&input)?)
    }
    fn from_base32_unpadded<T: AsRef<str>>(input: T) -> Result<MLDSA87SecretSeed,SlugErrors> {
        let input = SlugEncodingUsage::new(SlugEncodings::Base32unpadded).decode(input)?; 
        Ok(MLDSA87SecretSeed::from_bytes(&input)?)
    }
    fn from_base58<T: AsRef<str>>(input: T) -> Result<MLDSA87SecretSeed,SlugErrors> {
        let input = SlugEncodingUsage::new(SlugEncodings::Base58).decode(input)?; 
        Ok(MLDSA87SecretSeed::from_bytes(&input)?)
    }
    fn from_base64<T: AsRef<str>>(input: T) -> Result<MLDSA87SecretSeed,SlugErrors> {
        let input = SlugEncodingUsage::new(SlugEncodings::Base64).decode(input)?; 
        Ok(MLDSA87SecretSeed::from_bytes(&input)?)
    }
    fn from_base64_url_safe<T: AsRef<str>>(input: T) -> Result<MLDSA87SecretSeed,SlugErrors> {
        let input = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe).decode(input)?; 
        Ok(MLDSA87SecretSeed::from_bytes(&input)?)
    }
}

//=====END OF ENCODINGS=====//

//=====START OF PEM=====//

impl IntoStandardPem for MLDSA87PublicKey {
    fn into_standard_pem(&self) -> Result<String,SlugErrors> {
        let x: Vec<u8> = self.into_bincode()?;
        let pem = Pem::new(&Self::label_for_standard_pem(), x);
        return Ok(pem.to_string())
    }
    fn label_for_standard_pem() -> String {
        String::from("OpenInternetCryptographyProject/Standard/MLDSA87-Public-Key")
    }
    fn label_for_standard_pem_secret() -> String {
        String::from("OpenInternetCryptographyProject/Standard/MLDSA87-Secret-Key")
    }
}

impl IntoStandardPem for MLDSA87SecretKey {
    fn into_standard_pem(&self) -> Result<String,SlugErrors> {
        let x: Vec<u8> = self.into_bincode()?;
        let pem = Pem::new(&Self::label_for_standard_pem(), x);
        return Ok(pem.to_string())
    }
    fn label_for_standard_pem() -> String {
        String::from("OpenInternetCryptographyProject/Standard/MLDSA87-Secret-Key")
    }
    fn label_for_standard_pem_secret() -> String {
        String::from("OpenInternetCryptographyProject/Standard/MLDSA87-Secret-Key")
    }
}

impl IntoStandardPem for MLDSA87Signature {
    fn into_standard_pem(&self) -> Result<String,SlugErrors> {
        let x: Vec<u8> = self.into_bincode()?;
        let pem = Pem::new(&Self::label_for_standard_pem(), x);
        return Ok(pem.to_string())
    }
    fn label_for_standard_pem() -> String {
        String::from("OpenInternetCryptographyProject/Standard/MLDSA87-Signature")
    }
    fn label_for_standard_pem_secret() -> String {
        String::from("OpenInternetCryptographyProject/Standard/MLDSA87-Secret-Key")
    }
}

impl IntoStandardPem for MLDSA87SecretSeed {
    fn into_standard_pem(&self) -> Result<String,SlugErrors> {
        let x: Vec<u8> = self.into_bincode()?;
        let pem = Pem::new(&Self::label_for_standard_pem(), x);
        return Ok(pem.to_string())
    }
    fn label_for_standard_pem() -> String {
        String::from("OpenInternetCryptographyProject/Standard/MLDSA87-Secret-Seed")
    }
    fn label_for_standard_pem_secret() -> String {
        String::from("OpenInternetCryptographyProject/Standard/MLDSA87-Secret-Seed")
    }
}

impl FromStandardPem for MLDSA87PublicKey {
    fn from_standard_pem<T: AsRef<str>>(input: T) -> Result<MLDSA87PublicKey,SlugErrors> {
        let pem: Pem = Pem::from_str(input.as_ref()).unwrap();
        if pem.tag() != Self::label_for_standard_pem() {
            return Err(SlugErrors::Other(String::from("MLDSA87 Public Key From Standard Pem Failure")))
        }
        let decoded: MLDSA87PublicKey = Self::from_bincode(&pem.contents())?;
        Ok(decoded)
    }
}

impl FromStandardPem for MLDSA87SecretKey {
    fn from_standard_pem<T: AsRef<str>>(input: T) -> Result<MLDSA87SecretKey,SlugErrors> {
        let pem: Pem = Pem::from_str(input.as_ref()).unwrap();
        if pem.tag() != Self::label_for_standard_pem() {
            return Err(SlugErrors::Other(String::from("MLDSA87 Secret Key From Standard Pem Failure")))
        }
        let decoded: MLDSA87SecretKey = Self::from_bincode(&pem.contents())?;
        Ok(decoded)
    }
}

impl FromStandardPem for MLDSA87SecretSeed {
    fn from_standard_pem<T: AsRef<str>>(input: T) -> Result<MLDSA87SecretSeed,SlugErrors> {
        let pem: Pem = Pem::from_str(input.as_ref()).unwrap();
        if pem.tag() != Self::label_for_standard_pem() {
            return Err(SlugErrors::Other(String::from("MLDSA87 Secret Seed From Standard Pem Failure")))
        }
        let decoded: MLDSA87SecretSeed = Self::from_bincode(&pem.contents())?;
        Ok(decoded)
    }
}

impl FromStandardPem for MLDSA87Signature {
    fn from_standard_pem<T: AsRef<str>>(input: T) -> Result<MLDSA87Signature,SlugErrors> {
        let pem: Pem = Pem::from_str(input.as_ref()).unwrap();
        if pem.tag() != Self::label_for_standard_pem() {
            return Err(SlugErrors::Other(String::from("MLDSA87 Signature From Standard Pem Failure")))
        }
        let decoded: MLDSA87Signature = Self::from_bincode(&pem.contents())?;
        Ok(decoded)
    }
}

//=====END OF PEM=====
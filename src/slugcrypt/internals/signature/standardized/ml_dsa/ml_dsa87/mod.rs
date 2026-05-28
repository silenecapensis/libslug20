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
use rand_2::CryptoRng;
use securerand_rs::bip39::SlugMnemonic;
use serde::{Serialize,Deserialize};
use serde_big_array::BigArray;
use zeroize::{Zeroize,ZeroizeOnDrop};
use crate::errors::SlugErrors;

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
        let signature: &Result<Signature<MlDsa87>, _> = &self.into_secret_key_usable_type().try_sign(message.as_ref());

        if signature.is_ok() {
            let x: Signature<MlDsa87> = signature.unwrap().clone();
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
}
pub struct GenerateMLDSA87;

impl GenerateMLDSA87 {
    /// Generate a new ML-DSA87 key using randomness
    pub fn generate() {
        let key = SigningKey::<MlDsa87>::generate();
    }
    /// Generate a new ML-DSA87 key using the cryptorng trait.
    pub fn generate_from_rng<R: CryptoRng + ?Sized>(mut rng: &mut R) {
        let key = SigningKey::<MlDsa87>::generate_from_rng(&mut rng);
    }
}
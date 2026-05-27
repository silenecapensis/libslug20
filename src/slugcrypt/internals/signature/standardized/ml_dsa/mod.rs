use ml_dsa_new::MlDsa65;
use ml_dsa_new::Generate;
use ml_dsa_new::Keypair;
use ml_dsa_new::KeySizeUser;
use ml_dsa_new::KeyInit;
use ml_dsa_new::KeyExport;
use ml_dsa_new::MlDsaParams;
use ml_dsa_new::SignatureEncoding;
use ml_dsa_new::Signer;
use ml_dsa_new::Verifier;
use ml_dsa_new::{SigningKey,VerifyingKey};
use securerand_rs::bip39::SlugMnemonic;

pub struct SlugMLDSA65;

pub struct MLDSA65Seed {
    pub seed: [u8; 32]
}

pub struct MLDSA65PublicKey {
    pub pk: [u8; 1952]
}

pub struct MLDSA65SecretKey {
    pub sk: [u8; 4032]
}

pub struct MLDSA65Keypair {
    pub public_key: MLDSA65PublicKey,
    pub secret_key: MLDSA65SecretKey,
}

pub struct MLDSA65Signature {
    pub signature: [u8; 3309]
}

impl SlugMLDSA65 {
    pub fn generate_with_bip39_adv(bip39: SlugMnemonic, password: &str) -> MLDSA65Seed {
        let mut x: securerand_rs::bip39::MnemnonicSeed = bip39.to_seed_with_crypto(password).unwrap();
        let kp: SigningKey<MlDsa65> = SigningKey::generate_from_rng(&mut x);
        let bytes: Vec<u8> = kp.as_seed().to_vec();
        let mut seed: [u8; 32] = [0u8; 32];
        seed.copy_from_slice(&bytes[0..32]);
        MLDSA65Seed { seed: seed }
    }
}
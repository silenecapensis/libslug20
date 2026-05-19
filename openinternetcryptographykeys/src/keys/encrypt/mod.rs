use libslug::slugcrypt::internals::encrypt::aes256;
use libslug::slugcrypt::internals::encrypt::aes256::EncryptionKey;
use libslug::slugcrypt::internals::encrypt::chacha20;
use libslug::slugcrypt::internals::bip39::{SlugMnemonic, SlugBIP39Words};
use libslug::slugcrypt::internals::bip39::SlugBIP39Languages;
use libslug::slugcrypt::internals::bip39::traits::GenerateWithBIP39;
use slugencode::{SlugEncodingUsage,SlugEncodings};


pub struct OpenInternetSymmetricEncryption;

pub struct OpenInternetSymmetricEncryptionBIP39;

impl OpenInternetSymmetricEncryptionBIP39 {
    pub fn encrypt_aes256_with_bip39_without_password<U: AsRef<[u8]>>(msg: U, language: SlugBIP39Languages, word_size: SlugBIP39Words) -> ((aes256::AESCipherText,aes256::EncryptionNonce), SlugMnemonic) {
        let mnemonic: SlugMnemonic = SlugMnemonic::new(word_size, language);
        let seed: Vec<u8> = mnemonic.to_seed("").unwrap();
        let key = &seed[0..32];
        let encryption_key: EncryptionKey = aes256::EncryptionKey::from_bytes(key);
        let ciphertext: (aes256::AESCipherText, aes256::EncryptionNonce) = aes256::EncryptAES256::encrypt(encryption_key, msg.as_ref()).unwrap();
        return (ciphertext, mnemonic);
    }
    pub fn encrypt_aes256_with_bip39_with_password<T: AsRef<str>, U: AsRef<[u8]>>(msg: U, language: SlugBIP39Languages, word_size: SlugBIP39Words, password: T) -> ((aes256::AESCipherText,aes256::EncryptionNonce), SlugMnemonic) {
        let mnemonic: SlugMnemonic = SlugMnemonic::new(word_size, language);
        let seed: Vec<u8> = mnemonic.to_seed(password.as_ref()).unwrap();
        let key = &seed[0..32];
        let encryption_key: EncryptionKey = aes256::EncryptionKey::from_bytes(key);
        let ciphertext: (aes256::AESCipherText, aes256::EncryptionNonce) = aes256::EncryptAES256::encrypt(encryption_key, msg.as_ref()).unwrap();
        return (ciphertext, mnemonic);
    }
    pub fn decrypt_aes256_with_bip39_without_password<U: AsRef<[u8]>>(ciphertext: aes256::AESCipherText, nonce: aes256::EncryptionNonce, mnemonic: SlugMnemonic) -> Vec<u8> {
        let seed: Vec<u8> = mnemonic.to_seed("").unwrap();
        let key = &seed[0..32];
        let encryption_key: EncryptionKey = aes256::EncryptionKey::from_bytes(key);
        let plaintext: Vec<u8> = aes256::DecryptAES256::decrypt(encryption_key, nonce, ciphertext).unwrap();
        return plaintext;
    }
    pub fn decrypt_aes256_with_bip39_with_password<T: AsRef<str>, U: AsRef<[u8]>>(ciphertext: aes256::AESCipherText, nonce: aes256::EncryptionNonce, mnemonic: SlugMnemonic, password: T) -> Vec<u8> {
        let seed: Vec<u8> = mnemonic.to_seed(password.as_ref()).unwrap();
        let key = &seed[0..32];
        let encryption_key: EncryptionKey = aes256::EncryptionKey::from_bytes(key);
        let plaintext: Vec<u8> = aes256::DecryptAES256::decrypt(encryption_key, nonce, ciphertext).unwrap();
        return plaintext;
    }
    pub fn encrypt_xchacha20_with_bip39_without_password<U: AsRef<[u8]>>(msg: U, language: SlugBIP39Languages, word_size: SlugBIP39Words) -> ((chacha20::EncryptionCipherText, chacha20::EncryptionNonce), SlugMnemonic) {
        let mnemonic: SlugMnemonic = SlugMnemonic::new(word_size, language);
        let seed: Vec<u8> = mnemonic.to_seed("").unwrap();
        let key: &[u8] = &seed[0..32];
        let encoder: SlugEncodingUsage = SlugEncodingUsage::new(SlugEncodings::Hex);
        let key_in_hex: String = encoder.encode(key).unwrap();
        let encryption_key: chacha20::EncryptionKey = chacha20::EncryptionKey::from_hex(&key_in_hex).unwrap();
        let ciphertext: (chacha20::EncryptionCipherText, chacha20::EncryptionNonce) = chacha20::XChaCha20Encrypt::encrypt(encryption_key, msg.as_ref()).unwrap();
        return (ciphertext, mnemonic);
    }
    pub fn encrypt_xchacha20_with_bip39_with_password<T: AsRef<str>, U: AsRef<[u8]>>(msg: U, language: SlugBIP39Languages, word_size: SlugBIP39Words, password: T) -> ((chacha20::EncryptionCipherText, chacha20::EncryptionNonce), SlugMnemonic) {
        let mnemonic: SlugMnemonic = SlugMnemonic::new(word_size, language);
        let seed: Vec<u8> = mnemonic.to_seed(password.as_ref()).unwrap();
        let key: &[u8] = &seed[0..32];
        let encoder: SlugEncodingUsage = SlugEncodingUsage::new(SlugEncodings::Hex);
        let key_in_hex: String = encoder.encode(key).unwrap();
        let encryption_key: chacha20::EncryptionKey = chacha20::EncryptionKey::from_hex(&key_in_hex).unwrap();
        let ciphertext: (chacha20::EncryptionCipherText, chacha20::EncryptionNonce) = chacha20::XChaCha20Encrypt::encrypt(encryption_key, msg.as_ref()).unwrap();
        return (ciphertext, mnemonic);
    }
    pub fn decrypt_xchacha20_with_bip39_without_password<T: AsRef<str>, U: AsRef<[u8]>>(ciphertext: chacha20::EncryptionCipherText, nonce: chacha20::EncryptionNonce, mnemonic: SlugMnemonic) -> Vec<u8> {
        let seed: Vec<u8> = mnemonic.to_seed("").unwrap();
        let key: &[u8] = &seed[0..32];
        let encoder: SlugEncodingUsage = SlugEncodingUsage::new(SlugEncodings::Hex);
        let key_in_hex: String = encoder.encode(key).unwrap();
        let encryption_key: chacha20::EncryptionKey = chacha20::EncryptionKey::from_hex(&key_in_hex).unwrap();
        let plaintext: Vec<u8> = chacha20::XChaCha20Encrypt::decrypt(encryption_key, nonce, ciphertext).unwrap();
        return plaintext;
    }
    pub fn decrypt_xchacha20_with_bip39_with_password<T: AsRef<str>, U: AsRef<[u8]>>(ciphertext: chacha20::EncryptionCipherText, nonce: chacha20::EncryptionNonce, mnemonic: SlugMnemonic, password: T) -> Vec<u8> {
        let seed: Vec<u8> = mnemonic.to_seed(password.as_ref()).unwrap();
        let key: &[u8] = &seed[0..32];
        let encoder: SlugEncodingUsage = SlugEncodingUsage::new(SlugEncodings::Hex);
        let key_in_hex: String = encoder.encode(key).unwrap();
        let encryption_key: chacha20::EncryptionKey = chacha20::EncryptionKey::from_hex(&key_in_hex).unwrap();
        let plaintext: Vec<u8> = chacha20::XChaCha20Encrypt::decrypt(encryption_key, nonce, ciphertext).unwrap();
        return plaintext;
    }
}
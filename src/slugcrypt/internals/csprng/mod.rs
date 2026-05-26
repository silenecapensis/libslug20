/// # SlugCSPRNG
/// 
/// Init() initializes the CSPRNG with a password and seed from getrandom(). It uses Argon2id to derive the password. It then uses ChaCha20 to derive the secret.

use securerand_rs::securerand::SecureRandom;
use securerand_rs::rngs::FuschineCSPRNG;

/// # SlugCSPRNG
/// 
/// A CSPRNG using CHACHA20RNG and ARGON2ID
/// 
/// ```rust
/// use libslug::slugcrypt::csprng::SlugCSPRNG;
/// 
/// fn main() {
///     let password: &str = "Thisisapassword";
/// 
///     let csprng: [u8;32] = SlugCSPRNG::new(password);
/// }
/// ```
pub struct SlugCSPRNG;

impl SlugCSPRNG {
    /// Initializes the CSPRNG using CHACHA20RNG and Password Derived From Argon2id
    pub fn new(pass: &str) -> [u8;32] {
        SecureRandom::new(pass)
    }
    /// Generate Randomness From Operating System
    pub fn os_rand() -> [u8;32] {
        return FuschineCSPRNG::get_32_bytes_from_os();
    }
    /// Generates Randomness From Operating System (64 bytes)
    pub fn os_rand_64() -> [u8;64] {
        return FuschineCSPRNG::get_64_bytes_from_os()
    }
    /// Generates Randomness From Operating System (128 bytes)
    pub fn os_rand_128() -> [u8;128] {
        return FuschineCSPRNG::get_128_bytes_from_os()
    }
    /// An Esoteric Function For 33 bytes of randomness
    pub fn djb_33() -> [u8;33] {
        return FuschineCSPRNG::get_33_bytes_from_os()
    }
    /// Derive From Password Using Static Nonce
    /// 
    /// Warning: This is not the best option to use but is deterministic.
    pub fn derive_from_password(pass: &str) -> [u8;32] {
        SecureRandom::derive_from_password(pass)
    }
    /// Derives From Password Using A Salt of Your Choice
    /// 
    /// Best pratice is to use an OSCSPRNG and generate a salt that you keep and will be need to be held to determine the seed again
    pub fn derive_from_password_with_salt(pass: &str, salt: &str) -> [u8;32] {
        SecureRandom::derive_from_password_and_salt(pass, salt)
    }
    /// From Seed (32 bytes) Using CHACHA20RNG
    pub fn from_seed(seed: [u8;32]) -> [u8;32] {
        return FuschineCSPRNG::from_seed_32(seed)
    }
    /// From Seed (32 bytes) Using CHACHA20RNG returning 48
    pub fn from_seed_48(seed: [u8;32]) -> [u8;48] {
        return FuschineCSPRNG::from_seed_48(seed)
    }
    /// From Seed (32 bytes) Using CHACHA20RNG returning 64
    pub fn from_seed_64(seed: [u8;32]) -> [u8;64] {
        return FuschineCSPRNG::from_seed_64(seed)
    }
    /// From Seed (32 bytes) Using CHACHA20RNG returning 128
    pub fn from_seed_128(seed: [u8;32]) -> [u8;128] {
        return FuschineCSPRNG::from_seed_128(seed)
    }
}
use openinternetcryptographykeys::prelude::essentials::*;
use openinternetcryptographykeys::prelude::essentials::{OpenInternetFromStandardPEM,OpenInternetGeneration,OpenInternetFromPemAny,OpenInternetIntoStandardPEM,OpenInternetSigner,OpenInternetVerifier,OpenInternetPublicKeyDerive,OpenInternetAPIGeneration};

pub fn main() {
    let keypair: Result<OpenInternetCryptographyKeypair, libslug::prelude::core::SlugErrors> = OpenInternetCryptographyAPI::generate_with_algorithm(Slug20Algorithm::EsphandSigning);
    let keypair_pem = keypair.unwrap().into_secret_key().into_standard_pem().unwrap();
    let secret_key_from_pem: Result<OpenInternetCryptographySecretKey, libslug::prelude::core::SlugErrors> = OpenInternetCryptographySecretKey::from_standard_pem_with_algorithm(keypair_pem, Slug20Algorithm::EsphandSigning);
    let sig: Result<OpenInternetCryptographySignature, libslug::prelude::core::SlugErrors> = secret_key_from_pem.unwrap().sign("Hello World");
}
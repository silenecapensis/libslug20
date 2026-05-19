use openinternetcryptographykeys::prelude::essentials::*;
use openinternetcryptographykeys::prelude::essentials::{OpenInternetFromStandardPEM,OpenInternetGeneration,OpenInternetFromPemAny,OpenInternetIntoStandardPEM,OpenInternetSigner,OpenInternetVerifier};

fn main() {
    let keypair = OpenInternetCryptographySecretKey::generate_with_algorithm(Slug20Algorithm::ShulginSigning);
    let msg = "Hello World";
    let sig = keypair.unwrap().sign(msg).unwrap();
}

pub mod serde;
//! # BIP39
//! 
//! This module contains all required operations and functionality to use **BIP39**, a word generator that uses a seed to produce the secret key of certain algorithms.
//! 
//! ## Features
//! 
//! - [X] `SlugMnemonic``
//!     - [X] `fn New()`: Generates a new Mnemonic
//!     - [X] `fn from_phrase()`: Constructs SlugMnemonic struct from phrase and wordlist
//!     - [X] `fn to_mnemonic()`: Converts to bip39::Mnemonic
//!     - [X] `fn to_seed()`: Takes a password and wordlist then converts to seed (Vec<u8>)
//! 
//! ## TODO
//! 
//! - [ ] Number of Words
//! - [ ] Parsing

use bip39::{Mnemonic, MnemonicType, Language, Seed,ErrorKind};
use serde::{Serialize,Deserialize};
use rand_core::CryptoRng;
use rand_core::TryRng;

use zeroize::{Zeroize,ZeroizeOnDrop};

/// BIP39 Mnemonic Phrases: Traits
pub mod traits;

/// # SlugMnemonic
/// 
/// The default SlugMnemonic using `BIP39`.
/// 
/// ## Features
/// 
/// - [X] Number of Words
///     - [X] 12
///     - [X] 15
///     - [X] 18
///     - [X] 21
///     - [X] 24
/// - [X] Language
///     - [X] English
///     - [X] ChineseSimplified
///     - [X] ChineseTraditional
///     - [X] French
///     - [X] Italian
///     - [X] Japanese
///     - [X] Korean
///     - [X] Spanish
#[derive(Serialize,Deserialize,Zeroize,ZeroizeOnDrop,Clone, PartialEq, PartialOrd)]
pub struct SlugMnemonic {
    pub phrase: String,
    pub language: SlugBIP39Languages,
}

#[derive(Serialize,Deserialize,Zeroize,ZeroizeOnDrop,Clone,PartialEq,PartialOrd)]
pub enum SlugBIP39Languages {
    English,
    ChineseSimplified,
    ChineseTraditional,
    French,
    Italian,
    Japanese,
    Korean,
    Spanish,
}

#[derive(Serialize,Deserialize,Zeroize,ZeroizeOnDrop,Clone,PartialEq,PartialOrd)]
pub enum SlugBIP39Words {
    Words12,
    Words15,
    Words18,
    Words21,
    Words24,
}

impl SlugBIP39Languages {
    /// # Get Language
    /// 
    /// Returns Expected Language
    pub fn get_language(&self) -> Language {
        match self {
            SlugBIP39Languages::English => return Language::English,
            SlugBIP39Languages::ChineseSimplified => return Language::ChineseSimplified,
            SlugBIP39Languages::ChineseTraditional => return Language::ChineseTraditional,
            SlugBIP39Languages::French => return Language::French,
            SlugBIP39Languages::Italian => return Language::Italian,
            SlugBIP39Languages::Japanese => return Language::Japanese,
            SlugBIP39Languages::Korean => return Language::Korean,
            SlugBIP39Languages::Spanish => return Language::Spanish,
        }
    }
}

impl SlugBIP39Words {
    pub fn get_words(&self) -> MnemonicType {
        match &self {
            Self::Words12 => return MnemonicType::Words12,
            Self::Words15 => return MnemonicType::Words15,
            Self::Words18 => return MnemonicType::Words18,
            Self::Words21 => return MnemonicType::Words21,
            Self::Words24 => return MnemonicType::Words24,
        }
    }
}

impl SlugMnemonic {
    /// # New Mnemonic Phrase
    /// 
    /// Generate a new Mnemonic using a certain language and length.
    pub fn new(mnemonic_type: SlugBIP39Words, language: SlugBIP39Languages) -> Self {
        let phrase = Mnemonic::new(mnemonic_type.get_words(), language.get_language()).into_phrase();

        return Self {
            phrase: phrase,
            language: language,
        }
    }
    /// # From Phrase
    pub fn from_phrase<T: AsRef<str>>(phrase: T, language: SlugBIP39Languages) -> Result<Self,ErrorKind> {
        let phrase = Mnemonic::from_phrase(phrase.as_ref(), language.get_language())?.into_phrase();

        return Ok(Self {
            phrase: phrase,
            language: language,
        })
    }
    /// To Mnemonic
    pub fn to_mnemonic(&self) -> Result<Mnemonic,ErrorKind> {
        let mnemonic = Mnemonic::from_phrase(&self.phrase, self.language.get_language())?;

        return Ok(mnemonic)
    }
    /// # BIP39 Into Seed
    /// 
    /// Converts To Seed Using a Password
    pub fn to_seed<T: AsRef<str>>(&self, pass: T) -> Result<Vec<u8>,ErrorKind> {
        let mnemonic = self.to_mnemonic()?;
        let seed = Seed::new(&mnemonic, pass.as_ref());
        return Ok(seed.as_bytes().to_vec())
    }
    pub fn entropy(&self) -> Result<Vec<u8>,ErrorKind> {
        let x = &self.to_mnemonic()?;
        let entropy = x.entropy();
        Ok(entropy.to_vec())
    }
}
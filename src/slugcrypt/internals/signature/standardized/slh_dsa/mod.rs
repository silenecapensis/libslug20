//! # SLH-DSA (SPHINCS+)
//! 
//! ## Variants
//! 
//! s: small sigs, slow verifying
//! f: fast verifying, larger sigs
//! 
//! - SLH-DSA (Level 5) using SHAKE256s
//! - SLH-DSA (Level 5) using SHA2_256s
//! 
//! - SLH-DSA (Level 3) using SHAKE256s
//! - SLH-DSA (Level 3) using SHA2_256s
//! 
//! ## TODO:
//! 
//! - [ ] Add support for SLH-DSA (Level 5) using SHAKE256s

pub mod slh_dsa_shake256;
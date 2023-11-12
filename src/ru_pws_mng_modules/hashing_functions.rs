use ring::error::Unspecified;
use ring::rand::SecureRandom;
use ring::{digest, pbkdf2, rand};
use std::num::NonZeroU32;

fn n_iter() -> NonZeroU32 {
    NonZeroU32::new(100_000).unwrap()
}

pub fn hashing_function(password: &str) -> Result< ([u8; 64], [u8; 64]), Unspecified>{
    const CREDENTIAL_LEN: usize = digest::SHA512_OUTPUT_LEN;
    let rng = rand::SystemRandom::new();

    let mut salt = [0u8; CREDENTIAL_LEN];
    rng.fill(&mut salt)?;

    let mut pbkdf2_hash = [0u8; CREDENTIAL_LEN];
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA512, n_iter(), &salt, password.as_bytes(), &mut pbkdf2_hash);
    
    Ok((pbkdf2_hash, salt))
}

pub fn hash_checker(password: &str, hashed_password: &[u8; 64], salt: &[u8; 64]) -> bool {
    let result = pbkdf2::verify(pbkdf2::PBKDF2_HMAC_SHA512, n_iter(), salt, password.as_bytes(), hashed_password);
    result.is_ok()
}
use argon2::Argon2;
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

use crate::err::KeyGenerationError;

pub(crate) struct GeneratedKey {
    pub key: Vec<u8>,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
}

impl GeneratedKey {
    pub fn cleanup(&mut self) {
        self.key.zeroize();
        self.salt.zeroize();
        self.nonce.zeroize();
    }
}

pub(crate) fn generate_key(password: &str) -> Result<GeneratedKey, KeyGenerationError> {
    let salt = generate_random_salt(32);
    let nonce = generate_random_nonce(19);

    derive_key(password, salt, nonce)
}

pub(crate) fn derive_key(
    password: &str,
    salt: Vec<u8>,
    nonce: Vec<u8>,
) -> Result<GeneratedKey, KeyGenerationError> {
    let argon = setup_argon();
    let mut key_buffer = vec![0u8; 32];

    argon
        .hash_password_into(password.as_bytes(), &salt, &mut key_buffer)
        .map_err(|_| KeyGenerationError {})?;

    Ok(GeneratedKey {
        salt,
        nonce,
        key: key_buffer,
    })
}

fn generate_random_salt(size: usize) -> Vec<u8> {
    generate_random_buffer(size)
}

fn generate_random_nonce(size: usize) -> Vec<u8> {
    generate_random_buffer(size)
}

fn generate_random_buffer(size: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; size];
    OsRng.fill_bytes(&mut buffer);

    buffer
}

fn setup_argon() -> Argon2<'static> {
    Argon2::default()
}

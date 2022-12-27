extern crate core;

use std::error::Error;

use std::fs::File;
use std::io::{Read, Write};

use chacha20::XChaCha20;
use chacha20poly1305::aead::stream;
use chacha20poly1305::aead::stream::{Decryptor, Encryptor, StreamBE32};
use chacha20poly1305::consts::U24;
use chacha20poly1305::{ChaChaPoly1305, KeyInit, XChaCha20Poly1305};

use err::EncryptionError;

use crate::err::DecryptionError;

mod err;
mod keygen;

type Cypher = ChaChaPoly1305<XChaCha20, U24>;

const BUFFER_SIZE: usize = 1024;

pub fn encrypt_file(
    source_path: &str,
    target_path: &str,
    password: &str,
) -> Result<(), Box<dyn Error>> {
    let mut generated_key = keygen::generate_key(password)?;
    let nonce = generated_key.nonce.as_slice();
    let salt = generated_key.salt.as_slice();

    let aead = XChaCha20Poly1305::new(generated_key.key[..32].as_ref().into());
    let encryptor: Encryptor<Cypher, StreamBE32<Cypher>> =
        stream::EncryptorBE32::from_aead(aead, nonce.into());

    let mut source_file = File::open(source_path)?;
    let mut destination_file = File::create(target_path)?;

    write_header(&mut destination_file, salt, nonce)?;

    write_encrypted_file(&mut source_file, &mut destination_file, encryptor)?;

    generated_key.cleanup();

    Ok(())
}

pub fn decrypt_file(
    source_path: &str,
    target_path: &str,
    password: &str,
) -> Result<(), Box<dyn Error>> {
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 19];

    let mut source_file = File::open(source_path)?;
    let mut target_file = File::create(target_path)?;

    let mut bytes_read = source_file.read(&mut salt)?;
    if bytes_read != salt.len() {
        return Err(Box::new(DecryptionError::new(
            "Invalid file format".to_string(),
        )));
    }

    bytes_read = source_file.read(&mut nonce)?;
    if bytes_read != nonce.len() {
        return Err(Box::new(DecryptionError::new(
            "Invalid file format".to_string(),
        )));
    }

    let mut generated_key = keygen::derive_key(password, salt.to_vec(), nonce.to_vec())?;

    let aead = XChaCha20Poly1305::new(generated_key.key[..32].as_ref().into());
    let decryptor: Decryptor<Cypher, StreamBE32<Cypher>> =
        stream::DecryptorBE32::from_aead(aead, generated_key.nonce.as_slice().into());

    write_decrypted_file(&mut source_file, &mut target_file, decryptor)?;

    generated_key.cleanup();

    Ok(())
}

fn write_decrypted_file(
    src: &mut File,
    target: &mut File,
    mut decryptor: Decryptor<Cypher, StreamBE32<Cypher>>,
) -> Result<(), Box<dyn Error>> {
    let mut buffer = [0u8; BUFFER_SIZE];

    loop {
        let bytes_read = src.read(&mut buffer)?;
        let all_bytes_read = bytes_read < BUFFER_SIZE;
        let buffer_slice = &buffer[..bytes_read];

        if all_bytes_read {
            let plain_text = decryptor
                .decrypt_last(buffer_slice)
                .map_err(|e| DecryptionError::new(e.to_string()))?;
            target.write(&plain_text)?;
            return Ok(());
        } else {
            let plain_text = decryptor
                .decrypt_next(buffer_slice)
                .map_err(|e| DecryptionError::new(e.to_string()))?;
            target.write(&plain_text)?;
        }
    }
}

fn write_encrypted_file(
    src: &mut File,
    target: &mut File,
    mut encryptor: Encryptor<Cypher, StreamBE32<Cypher>>,
) -> Result<(), Box<dyn Error>> {
    let mut buffer = [0u8; BUFFER_SIZE];

    loop {
        let bytes_read = src.read(&mut buffer)?;
        let all_bytes_read = bytes_read < BUFFER_SIZE;
        let buffer_slice = &buffer[..bytes_read];

        if all_bytes_read {
            let cipher_text = encryptor
                .encrypt_last(buffer_slice)
                .map_err(|e| EncryptionError::new(e.to_string()))?;
            target.write(&cipher_text)?;
            return Ok(());
        } else {
            let cipher_text = encryptor
                .encrypt_next(buffer_slice)
                .map_err(|e| EncryptionError::new(e.to_string()))?;
            target.write(&cipher_text)?;
        }
    }
}

fn write_header(file: &mut File, salt: &[u8], nonce: &[u8]) -> Result<(), EncryptionError> {
    file.write(salt)
        .map_err(|e| EncryptionError::new(e.to_string()))?;
    file.write(nonce)
        .map_err(|e| EncryptionError::new(e.to_string()))?;

    Ok(())
}

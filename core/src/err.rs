use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub struct EncryptionError {
    pub msg: String,
}

impl Display for EncryptionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Could not encrypt file: {}", self.msg)
    }
}

impl Error for EncryptionError {}

impl EncryptionError {
    pub(crate) fn new(msg: String) -> Self {
        Self { msg }
    }
}

#[derive(Debug)]
pub struct DecryptionError {
    pub msg: String,
}

impl Display for DecryptionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Could not decrypt file: {}", self.msg)
    }
}

impl Error for DecryptionError {}

impl DecryptionError {
    pub(crate) fn new(msg: String) -> Self {
        Self { msg }
    }
}

#[derive(Debug)]
pub struct KeyGenerationError;

impl Display for KeyGenerationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Could not generate/derive key")
    }
}

impl Error for KeyGenerationError {}

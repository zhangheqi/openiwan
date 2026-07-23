//! Cryptographic primitives used by the traditional iWAN data plane.
//!
//! These algorithms are protocol compatibility requirements, not modern
//! cryptographic recommendations. In particular, XOR and AES-ECB do not provide
//! authenticated encryption.

use crate::{EncryptionMethod, Error, Result};
use aes::Aes128;
use cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use md5::Digest;
use zeroize::Zeroize;

pub const KEY_LEN: usize = 16;
pub const AES_BLOCK_LEN: usize = 16;

pub fn md5(data: &[u8]) -> [u8; KEY_LEN] {
    let digest = md5::Md5::digest(data);
    let mut output = [0_u8; KEY_LEN];
    output.copy_from_slice(&digest);
    output
}

/// Derive the data-plane session key: `MD5(username || password)`.
pub fn derive_session_key(username: &str, password: &str) -> [u8; KEY_LEN] {
    let mut input = Vec::with_capacity(username.len() + password.len());
    input.extend_from_slice(username.as_bytes());
    input.extend_from_slice(password.as_bytes());
    let key = md5(&input);
    input.zeroize();
    key
}

/// Derive the password wrapping key: `MD5("mw" || username)`.
pub fn derive_password_key(username: &str) -> [u8; KEY_LEN] {
    let mut input = Vec::with_capacity(2 + username.len());
    input.extend_from_slice(b"mw");
    input.extend_from_slice(username.as_bytes());
    let key = md5(&input);
    input.zeroize();
    key
}

/// Encrypt the fixed-size password field used in an OPEN packet.
///
/// The official 2.3.0 client copies at most the first 16 UTF-8 bytes and pads
/// the remainder with zero bytes before one AES-128-ECB block encryption.
pub fn encrypt_password(password: &str, username: &str) -> [u8; KEY_LEN] {
    let mut key = derive_password_key(username);
    let mut block = [0_u8; AES_BLOCK_LEN];
    let password_bytes = password.as_bytes();
    let copy_len = password_bytes.len().min(AES_BLOCK_LEN);
    block[..copy_len].copy_from_slice(&password_bytes[..copy_len]);

    let cipher = Aes128::new(GenericArray::from_slice(&key));
    let mut generic_block = GenericArray::clone_from_slice(&block);
    cipher.encrypt_block(&mut generic_block);
    block.copy_from_slice(&generic_block);
    key.zeroize();
    block
}

pub trait DataCipher: Send + Sync + std::fmt::Debug {
    fn method(&self) -> EncryptionMethod;
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

#[derive(Debug, Default)]
pub struct NoCipher;

impl DataCipher for NoCipher {
    fn method(&self) -> EncryptionMethod {
        EncryptionMethod::None
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        Ok(plaintext.to_vec())
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        Ok(ciphertext.to_vec())
    }
}

#[derive(Clone)]
pub struct XorCipher {
    key: [u8; KEY_LEN],
}

impl XorCipher {
    pub const fn new(key: [u8; KEY_LEN]) -> Self {
        Self { key }
    }

    fn apply(&self, input: &[u8]) -> Vec<u8> {
        input
            .iter()
            .zip(self.key.iter().cycle())
            .map(|(byte, key)| byte ^ key)
            .collect()
    }
}

impl std::fmt::Debug for XorCipher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("XorCipher([REDACTED])")
    }
}

impl Drop for XorCipher {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl DataCipher for XorCipher {
    fn method(&self) -> EncryptionMethod {
        EncryptionMethod::Xor
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        Ok(self.apply(plaintext))
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        Ok(self.apply(ciphertext))
    }
}

#[derive(Clone)]
pub struct AesCipher {
    key: [u8; KEY_LEN],
}

impl AesCipher {
    pub const fn new(key: [u8; KEY_LEN]) -> Self {
        Self { key }
    }
}

impl std::fmt::Debug for AesCipher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AesCipher([REDACTED])")
    }
}

impl Drop for AesCipher {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl DataCipher for AesCipher {
    fn method(&self) -> EncryptionMethod {
        EncryptionMethod::Aes
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.is_empty() {
            return Ok(Vec::new());
        }

        let padded_len = plaintext.len().div_ceil(AES_BLOCK_LEN) * AES_BLOCK_LEN;
        let mut output = vec![0_u8; padded_len];
        output[..plaintext.len()].copy_from_slice(plaintext);
        let cipher = Aes128::new(GenericArray::from_slice(&self.key));
        for block in output.chunks_exact_mut(AES_BLOCK_LEN) {
            cipher.encrypt_block(GenericArray::from_mut_slice(block));
        }
        Ok(output)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() % AES_BLOCK_LEN != 0 {
            return Err(Error::Crypto(
                "AES ciphertext length is not a multiple of 16",
            ));
        }
        let mut output = ciphertext.to_vec();
        let cipher = Aes128::new(GenericArray::from_slice(&self.key));
        for block in output.chunks_exact_mut(AES_BLOCK_LEN) {
            cipher.decrypt_block(GenericArray::from_mut_slice(block));
        }
        Ok(output)
    }
}

pub fn create_cipher(
    method: EncryptionMethod,
    username: &str,
    password: &str,
) -> Box<dyn DataCipher> {
    match method {
        EncryptionMethod::None => Box::new(NoCipher),
        EncryptionMethod::Xor => Box::new(XorCipher::new(derive_session_key(username, password))),
        EncryptionMethod::Aes => Box::new(AesCipher::new(derive_session_key(username, password))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_matches_standard_vector() {
        assert_eq!(
            md5(b"abc"),
            [
                0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1,
                0x7f, 0x72
            ]
        );
    }

    #[test]
    fn xor_round_trip() {
        let cipher = XorCipher::new([0x5a; KEY_LEN]);
        assert_eq!(format!("{cipher:?}"), "XorCipher([REDACTED])");
        let ciphertext = cipher.encrypt(b"openiwan").unwrap();
        assert_eq!(cipher.decrypt(&ciphertext).unwrap(), b"openiwan");
    }

    #[test]
    fn aes_round_trip_and_zero_padding() {
        let cipher = AesCipher::new([0x11; KEY_LEN]);
        let ciphertext = cipher.encrypt(b"twenty-one byte input").unwrap();
        assert_eq!(ciphertext.len(), 32);
        let plaintext = cipher.decrypt(&ciphertext).unwrap();
        assert_eq!(&plaintext[..21], b"twenty-one byte input");
        assert!(plaintext[21..].iter().all(|byte| *byte == 0));
    }
}

//! Cryptographic primitives used by the traditional iWAN data plane.
//!
//! These algorithms are wire-protocol requirements, not modern
//! cryptographic recommendations. In particular, XOR and AES-ECB do not provide
//! authenticated encryption.

use crate::{EncryptionMethod, Error, Result};
use aes::Aes128;
use cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use md5::Digest;
use zeroize::Zeroize;

pub const KEY_LEN: usize = 16;
pub const AES_BLOCK_LEN: usize = 16;
pub const XOR_KEY_LEN: usize = 8;

pub fn md5(data: &[u8]) -> [u8; KEY_LEN] {
    let digest = md5::Md5::digest(data);
    let mut output = [0_u8; KEY_LEN];
    output.copy_from_slice(&digest);
    output
}

/// Reproduce Java `String.getBytes(StandardCharsets.US_ASCII)`.
///
/// Java's default replacement for an unmappable character in US-ASCII is
/// `?`. A Unicode scalar therefore contributes either its ASCII byte or one
/// replacement byte.
pub fn java_us_ascii(value: &str) -> Vec<u8> {
    value
        .chars()
        .map(|character| {
            if character.is_ascii() {
                character as u8
            } else {
                b'?'
            }
        })
        .collect()
}

/// Derive the data-plane session key: `MD5(ASCII(username || password))`.
pub fn derive_session_key(username: &str, password: &str) -> [u8; KEY_LEN] {
    let mut input = java_us_ascii(username);
    input.extend_from_slice(&java_us_ascii(password));
    let key = md5(&input);
    input.zeroize();
    key
}

/// Derive the password wrapping key: `MD5("mw" || ASCII(username))`.
pub fn derive_password_key(username: &str) -> [u8; KEY_LEN] {
    let mut input = Vec::with_capacity(2 + username.len());
    input.extend_from_slice(b"mw");
    input.extend_from_slice(&java_us_ascii(username));
    let key = md5(&input);
    input.zeroize();
    key
}

/// Encrypt the fixed-size password field used in an OPEN packet.
///
/// The password is converted to Java-compatible US-ASCII, truncated to 16
/// bytes, zero-padded, and encrypted as one AES-128-ECB block.
pub fn encrypt_password(password: &str, username: &str) -> [u8; KEY_LEN] {
    let mut key = derive_password_key(username);
    let mut block = [0_u8; AES_BLOCK_LEN];
    let mut password_bytes = java_us_ascii(password);
    let copy_len = password_bytes.len().min(AES_BLOCK_LEN);
    block[..copy_len].copy_from_slice(&password_bytes[..copy_len]);
    password_bytes.zeroize();

    let cipher = Aes128::new(&Array::from(key));
    let mut generic_block = Array::from(block);
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
            .zip(self.key[..XOR_KEY_LEN].iter().cycle())
            .map(|(byte, key)| byte ^ key)
            .collect()
    }
}

impl std::fmt::Debug for XorCipher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("XorCipher")
            .field("key", &"[REDACTED]")
            .finish()
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
        let cipher = Aes128::new(&Array::from(self.key));
        for block in output.chunks_exact_mut(AES_BLOCK_LEN) {
            cipher.encrypt_block(block.try_into().expect("AES block length is fixed"));
        }
        Ok(output)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if !ciphertext.len().is_multiple_of(AES_BLOCK_LEN) {
            return Err(Error::Crypto(
                "AES ciphertext length is not a multiple of 16",
            ));
        }
        let mut output = ciphertext.to_vec();
        let cipher = Aes128::new(&Array::from(self.key));
        for block in output.chunks_exact_mut(AES_BLOCK_LEN) {
            cipher.decrypt_block(block.try_into().expect("AES block length is fixed"));
        }
        Ok(output)
    }
}

pub fn create_cipher(
    method: EncryptionMethod,
    username: &str,
    password: &str,
) -> Result<Box<dyn DataCipher>> {
    Ok(match method {
        EncryptionMethod::None => Box::new(NoCipher),
        EncryptionMethod::Xor => Box::new(XorCipher {
            key: derive_session_key(username, password),
        }),
        EncryptionMethod::Aes => Box::new(AesCipher::new(derive_session_key(username, password))),
    })
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
        assert_eq!(format!("{cipher:?}"), "XorCipher { key: \"[REDACTED]\" }");
        let ciphertext = cipher.encrypt(b"openiwan").unwrap();
        assert_eq!(cipher.decrypt(&ciphertext).unwrap(), b"openiwan");
    }

    #[test]
    fn xor_key_repeats_after_eight_bytes() {
        let key = [
            0, 1, 2, 3, 4, 5, 6, 7, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        ];
        let cipher = XorCipher::new(key);
        assert_eq!(
            cipher.encrypt(&[0_u8; 16]).unwrap(),
            [0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7]
        );
    }

    #[test]
    fn xor_matches_specification_vector() {
        let cipher = XorCipher::new(derive_session_key("alice", "secret"));
        let plain = [
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0xc0, 0x00,
            0x02, 0x01, 0xc6, 0x33, 0x64, 0x02,
        ];
        assert_eq!(
            cipher.encrypt(&plain).unwrap(),
            [
                0x81, 0xe3, 0x13, 0x07, 0x22, 0x2c, 0xf0, 0x5f, 0x84, 0xe2, 0x13, 0x13, 0xe2, 0x2c,
                0xf2, 0x5e, 0x02, 0xd0, 0x77, 0x11
            ]
        );
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

    #[test]
    fn session_aes_matches_specification_vector() {
        let cipher = AesCipher::new(derive_session_key("alice", "secret"));
        let plain = [
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0xc0, 0x00,
            0x02, 0x01, 0xc6, 0x33, 0x64, 0x02,
        ];
        assert_eq!(
            cipher.encrypt(&plain).unwrap(),
            [
                0x44, 0x4d, 0x65, 0x8f, 0x5b, 0xb3, 0x0e, 0x9a, 0x09, 0x9e, 0x02, 0x95, 0xe2, 0x1f,
                0xf1, 0x18, 0x49, 0x6f, 0x56, 0x63, 0xd9, 0x78, 0x0f, 0x85, 0x2b, 0xa4, 0xf9, 0xc6,
                0xc7, 0x5d, 0xf2, 0x55
            ]
        );
    }

    #[test]
    fn java_ascii_replaces_unmappable_characters() {
        assert_eq!(java_us_ascii("a中🙂z"), b"a??z");
    }
}

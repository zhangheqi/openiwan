use super::security;
use crate::{Error, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;
const MINIMUM_PAYLOAD_LENGTH: usize = NONCE_LENGTH + TAG_LENGTH + 1;

/// Decrypt a controller-generated `SaaS` ingress password.
///
/// The recovered client selects the controller secret from the controller app
/// ID saved during lookup. The AES-256 key is SHA-256 over the UTF-8 string
/// `secret|complete_domain|username`. The standard Base64 payload is
/// `nonce[12] || ciphertext || tag[16]`; AES-GCM authenticates the UTF-8 AAD
/// `complete_domain|username`.
pub(crate) fn decrypt_saas_password(
    app_id: &str,
    complete_domain: &str,
    username: &str,
    encoded: &str,
) -> Result<String> {
    if encoded.is_empty() {
        return Err(Error::Crypto("empty SaaS password payload"));
    }
    if complete_domain.is_empty() {
        return Err(Error::Crypto("empty SaaS credential domain"));
    }
    if username.is_empty() {
        return Err(Error::Crypto("empty SaaS credential username"));
    }

    let payload = Zeroizing::new(
        STANDARD
            .decode(encoded)
            .map_err(|_| Error::Crypto("invalid SaaS password Base64"))?,
    );
    if payload.len() < MINIMUM_PAYLOAD_LENGTH {
        return Err(Error::Crypto("SaaS password payload is too short"));
    }

    let nonce_bytes: [u8; NONCE_LENGTH] = payload[..NONCE_LENGTH]
        .try_into()
        .map_err(|_| Error::Crypto("invalid SaaS password nonce"))?;
    let secret = Zeroizing::new(security::controller_secret(app_id)?);
    let key_material = Zeroizing::new(format!("{}|{complete_domain}|{username}", secret.as_str()));
    let mut key_bytes = Zeroizing::new(Sha256::digest(key_material.as_bytes()).to_vec());
    let unbound = UnboundKey::new(&aead::AES_256_GCM, key_bytes.as_slice())
        .map_err(|_| Error::Crypto("invalid SaaS password key"))?;
    key_bytes.zeroize();
    let aad = Zeroizing::new(format!("{complete_domain}|{username}"));
    let mut plaintext = Zeroizing::new(payload.to_vec());
    let plaintext = LessSafeKey::new(unbound)
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(aad.as_bytes()),
            &mut plaintext[NONCE_LENGTH..],
        )
        .map_err(|_| Error::Crypto("SaaS password authentication failed"))?;
    std::str::from_utf8(plaintext)
        .map(ToOwned::to_owned)
        .map_err(|_| Error::Crypto("SaaS password is not UTF-8"))
}

#[cfg(test)]
pub(crate) fn encrypt_for_test(
    app_id: &str,
    complete_domain: &str,
    username: &str,
    plaintext: &[u8],
) -> String {
    let secret = security::controller_secret(app_id).unwrap();
    let key_material = format!("{secret}|{complete_domain}|{username}");
    let key_bytes = Sha256::digest(key_material.as_bytes());
    let unbound = UnboundKey::new(&aead::AES_256_GCM, key_bytes.as_slice()).unwrap();
    let key = LessSafeKey::new(unbound);
    let nonce = [0x5a; NONCE_LENGTH];
    let mut ciphertext = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(format!("{complete_domain}|{username}").as_bytes()),
        &mut ciphertext,
    )
    .unwrap();
    let mut payload = nonce.to_vec();
    payload.extend_from_slice(&ciphertext);
    STANDARD.encode(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypts_recovered_saas_payload_layout() {
        let encoded = encrypt_for_test(
            "controller-example",
            "example.test",
            "entry-user",
            b"generated-pass",
        );
        assert_eq!(
            decrypt_saas_password("controller-example", "example.test", "entry-user", &encoded,)
                .unwrap(),
            "generated-pass"
        );
    }

    #[test]
    fn rejects_short_and_tampered_payloads() {
        assert!(
            decrypt_saas_password("controller-example", "example.test", "entry-user", "AA==",)
                .is_err()
        );

        let encoded = encrypt_for_test(
            "controller-example",
            "example.test",
            "entry-user",
            b"generated-pass",
        );
        let mut payload = STANDARD.decode(encoded).unwrap();
        let last = payload.len() - 1;
        payload[last] ^= 1;
        assert!(
            decrypt_saas_password(
                "controller-example",
                "example.test",
                "entry-user",
                &STANDARD.encode(payload)
            )
            .is_err()
        );
    }
}

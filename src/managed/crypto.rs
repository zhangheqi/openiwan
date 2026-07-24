use super::provider::ProviderConfig;
use super::store::ManagedServer;
use crate::{Error, Result};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub fn decrypt_server_password(
    provider: &ProviderConfig,
    server: &ManagedServer,
) -> Result<Zeroizing<String>> {
    let mut key_input = format!(
        "{}|{}|{}",
        provider.controller.app_secret, provider.controller.domain, server.username
    );
    let key = Sha256::digest(key_input.as_bytes());
    zeroize::Zeroize::zeroize(&mut key_input);

    let encoded = &server.encrypted_password;
    let data = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(encoded))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded))
        .map_err(|_| Error::Controller("line password is not valid base64".into()))?;
    if data.len() < 28 {
        return Err(Error::Controller(
            "encrypted line password is too short".into(),
        ));
    }
    let nonce = Nonce::from_slice(&data[..12]);
    let aad = format!("{}|{}", provider.controller.domain, server.username);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| Error::Crypto("invalid managed password key"))?;
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &data[12..],
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| Error::Controller("line password authentication failed".into()))?;
    let password = String::from_utf8(plaintext)
        .map_err(|_| Error::Controller("line password is not valid UTF-8".into()))?;
    Ok(Zeroizing::new(password))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed::provider::{
        ControllerConfig, OidcConfig, PROVIDER_VERSION, TokenRequestFormat,
    };
    use aes_gcm::aead::Aead;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    fn provider() -> ProviderConfig {
        ProviderConfig {
            version: PROVIDER_VERSION,
            id: "test".into(),
            display_name: "Test".into(),
            dns_servers: Vec::new(),
            require_auth_verify_echo: false,
            xor_key_bytes: 16,
            oidc: OidcConfig {
                issuer: "https://auth.example.test".into(),
                client_id: "client".into(),
                redirect_uri: "com.example://callback".into(),
                scopes: vec!["openid".into()],
                username_claims: vec!["sub".into()],
                token_request_format: TokenRequestFormat::Json,
            },
            controller: ControllerConfig {
                base_url: "https://controller.example.test".into(),
                domain: "iwan.example".into(),
                app_id: "app".into(),
                app_secret: "secret".into(),
                auth_path: "/m/auth".into(),
                keepalive_path: "/m/keepalive".into(),
                config_path: "/m/config".into(),
                device_type: "android".into(),
                oem_name: "example-oem".into(),
            },
        }
    }

    #[test]
    fn decrypts_and_authenticates_password() {
        let provider = provider();
        let username = "line-user";
        let key = Sha256::digest(
            format!(
                "{}|{}|{username}",
                provider.controller.app_secret, provider.controller.domain
            )
            .as_bytes(),
        );
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = [7_u8; 12];
        let aad = format!("{}|{username}", provider.controller.domain);
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: b"line-password",
                    aad: aad.as_bytes(),
                },
            )
            .unwrap();
        let mut wire = nonce.to_vec();
        wire.extend_from_slice(&encrypted);
        let server = ManagedServer {
            name: "Line".into(),
            host: "192.0.2.1".into(),
            port: 6001,
            username: username.into(),
            encrypted_password: URL_SAFE_NO_PAD.encode(wire),
        };

        assert_eq!(
            decrypt_server_password(&provider, &server)
                .unwrap()
                .as_str(),
            "line-password"
        );

        let mut tampered = server;
        tampered.encrypted_password.push('A');
        assert!(decrypt_server_password(&provider, &tampered).is_err());
    }
}

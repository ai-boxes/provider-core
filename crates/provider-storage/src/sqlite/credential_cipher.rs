use super::*;

#[derive(Clone)]
pub(super) struct CredentialCipher {
    cipher: XChaCha20Poly1305,
}

const CREDENTIAL_CIPHERTEXT_VERSION: &str = "v1";
const CREDENTIAL_NONCE_BYTES: usize = 24;

impl CredentialCipher {
    pub(super) fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new((&key).into()),
        }
    }

    pub(super) fn encrypt(
        &self,
        account_id: &AccountId,
        plaintext: &SecretString,
    ) -> Result<String, AccountRepositoryError> {
        let mut nonce = [0_u8; CREDENTIAL_NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|error| {
            repository_error("failed to generate provider credential nonce", error)
        })?;
        let nonce_value = XNonce::from(nonce);
        let ciphertext = self
            .cipher
            .encrypt(
                &nonce_value,
                Payload {
                    msg: plaintext.expose_secret().as_bytes(),
                    aad: account_id.as_str().as_bytes(),
                },
            )
            .map_err(|_| AccountRepositoryError::new("failed to encrypt provider credential"))?;
        let mut encoded = Vec::with_capacity(nonce.len() + ciphertext.len());
        encoded.extend_from_slice(&nonce);
        encoded.extend_from_slice(&ciphertext);
        Ok(format!(
            "{CREDENTIAL_CIPHERTEXT_VERSION}:{}",
            STANDARD_NO_PAD.encode(encoded)
        ))
    }

    pub(super) fn decrypt(
        &self,
        account_id: &AccountId,
        encoded: &str,
    ) -> Result<SecretString, AccountRepositoryError> {
        let payload = encoded.strip_prefix("v1:").ok_or_else(|| {
            AccountRepositoryError::new("unsupported provider credential ciphertext version")
        })?;
        let payload = STANDARD_NO_PAD.decode(payload).map_err(|_| {
            AccountRepositoryError::new("provider credential ciphertext is not valid base64")
        })?;
        if payload.len() <= CREDENTIAL_NONCE_BYTES {
            return Err(AccountRepositoryError::new(
                "provider credential ciphertext is truncated",
            ));
        }
        let (nonce, ciphertext) = payload.split_at(CREDENTIAL_NONCE_BYTES);
        let nonce: [u8; CREDENTIAL_NONCE_BYTES] = nonce
            .try_into()
            .map_err(|_| AccountRepositoryError::new("provider credential nonce is invalid"))?;
        let nonce = XNonce::from(nonce);
        let plaintext = self
            .cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: account_id.as_str().as_bytes(),
                },
            )
            .map_err(|_| AccountRepositoryError::new("failed to decrypt provider credential"))?;
        String::from_utf8(plaintext)
            .map(SecretString::from)
            .map_err(|_| AccountRepositoryError::new("provider credential plaintext is not UTF-8"))
    }
}

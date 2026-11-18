// SPDX-License-Identifier: MIT
//! Arq7 decryption.
//!
//! ## Key derivation (encryptedkeyset.dat)
//! Header: "ARQ_ENCRYPTED_MASTER_KEYS" (25 bytes, no newline) + salt(8) + HMAC-SHA256(32)
//!   + IV(16) + ciphertext_of_all_three_keys(variable, PKCS7-padded)
//!
//! PBKDF2 derives 64 bytes: first 32 = AES key, last 32 = HMAC key
//!
//! Plaintext keyset format (after decryption):
//!   [u32: encryption_version = 3]
//!   [u64: enc_key_len]  [enc_key: enc_key_len bytes]       -- key 0: AES encryption key
//!   [u64: hmac_key_len] [hmac_key: hmac_key_len bytes]     -- key 1: HMAC key
//!   [u64: id_salt_len]  [id_salt: id_salt_len bytes]       -- key 2: blob identifier salt
//!
//! ## Encrypted object (ARQO)
//! Format:
//!   "ARQO" (4 bytes)
//!   HMAC-SHA256 of (master_iv + enc_session_blob + ciphertext) using key[1]   (32 bytes)
//!   master_iv                                                                   (16 bytes)
//!   enc_session_blob = AES-CBC(key[0], master_iv, data_iv || session_key)      (64 bytes)
//!   ciphertext = AES-CBC(session_key, data_iv, plaintext)                      (variable)

use aes::Aes256;
use anyhow::{Context, Result, bail};
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use sha2::Sha256;

const HEADER: &[u8] = b"ARQ_ENCRYPTED_MASTER_KEYS";
const PBKDF2_ROUNDS: u32 = 200_000;
const IV_SIZE: usize = 16;
const HMAC_SIZE: usize = 32;
const SALT_SIZE: usize = 8; // official: ARQ7_KEYSET_SALT_LEN = 8
const ARQO_MAGIC: &[u8] = b"ARQO";
// enc_session_blob = IV(16 bytes) + AES-CBC(data_iv(16) + session_key(32)) = 16 + 48 = 64
const ENC_SESSION_BLOB_SIZE: usize = 64;

/// The three variable-length master keys derived from the user's password.
///
/// - `keys[0]`: AES encryption key (64 bytes in practice, first 32 used)
/// - `keys[1]`: HMAC key
/// - `keys[2]`: blob identifier salt
pub struct Arq7Keys {
    pub keys: [Vec<u8>; 3],
}

impl Arq7Keys {
    /// Derive keys from `encryptedkeyset.dat` content and the user's password.
    pub fn from_dat(dat: &[u8], password: &str) -> Result<Self> {
        if !dat.starts_with(HEADER) {
            bail!("missing ARQ_ENCRYPTED_MASTER_KEYS header");
        }

        let body = &dat[HEADER.len()..];
        if body.len() < SALT_SIZE + HMAC_SIZE + IV_SIZE + 16 {
            bail!("encryptedkeyset.dat body too short: {} bytes", body.len());
        }

        let salt = &body[..SALT_SIZE];
        let stored_hmac = &body[SALT_SIZE..SALT_SIZE + HMAC_SIZE];
        let iv = &body[SALT_SIZE + HMAC_SIZE..SALT_SIZE + HMAC_SIZE + IV_SIZE];
        let ciphertext = &body[SALT_SIZE + HMAC_SIZE + IV_SIZE..];

        // Derive 64 bytes: first 32 = AES key, last 32 = HMAC key
        let mut derived = [0u8; 64];
        pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, PBKDF2_ROUNDS, &mut derived)
            .context("PBKDF2 derivation failed")?;
        let aes_key = &derived[..32];
        let hmac_key = &derived[32..];

        // Verify HMAC over (IV + ciphertext)
        let hmac_data = &body[SALT_SIZE + HMAC_SIZE..];
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(hmac_key).context("HMAC key init failed")?;
        mac.update(hmac_data);
        mac.verify_slice(stored_hmac)
            .map_err(|_| anyhow::anyhow!("HMAC verification failed — wrong password?"))?;

        // Decrypt the keyset using AES key
        let mut buf = ciphertext.to_vec();
        let plaintext = cbc::Decryptor::<Aes256>::new_from_slices(aes_key, iv)
            .context("AES init failed for keyset")?
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|e| anyhow::anyhow!("PKCS7 unpad failed for keyset: {e:?}"))?;

        // Parse the plaintext keyset
        // [u32: version=3] [u64: len][key] [u64: len][key] [u64: len][key]
        if plaintext.len() < 4 {
            bail!("keyset plaintext too short");
        }
        let version = u32::from_be_bytes(plaintext[0..4].try_into().unwrap());
        if version != 3 {
            bail!("unexpected keyset version {version}");
        }

        let mut offset = 4;
        let mut parsed_keys: Vec<Vec<u8>> = Vec::with_capacity(3);
        for i in 0..3 {
            if offset + 8 > plaintext.len() {
                bail!("keyset plaintext truncated at key {i} length");
            }
            let len =
                u64::from_be_bytes(plaintext[offset..offset + 8].try_into().unwrap()) as usize;
            offset += 8;
            if offset + len > plaintext.len() {
                bail!("keyset plaintext truncated at key {i} data");
            }
            parsed_keys.push(plaintext[offset..offset + len].to_vec());
            offset += len;
        }

        Ok(Self {
            keys: [
                parsed_keys.remove(0),
                parsed_keys.remove(0),
                parsed_keys.remove(0),
            ],
        })
    }

    /// Decrypt an ARQO-format encrypted object.
    #[allow(dead_code)]
    pub fn decrypt_object(&self, data: &[u8]) -> Result<Vec<u8>> {
        decrypt_arq7_object(data, self)
    }
}

/// Decrypt an Arq7 ARQO-format encrypted object.
///
/// Format: "ARQO" + HMAC(32) + master_iv(16) + enc_session_blob(64) + ciphertext(...)
pub fn decrypt_arq7_object(data: &[u8], keys: &Arq7Keys) -> Result<Vec<u8>> {
    let min_len = ARQO_MAGIC.len() + HMAC_SIZE + IV_SIZE + ENC_SESSION_BLOB_SIZE;
    if data.len() < min_len {
        bail!(
            "encrypted object too short: {} bytes (need {min_len})",
            data.len()
        );
    }

    if &data[..4] != ARQO_MAGIC {
        bail!("missing ARQO magic (got {:?})", &data[..4]);
    }

    let stored_hmac = &data[4..4 + HMAC_SIZE];
    let master_iv = &data[4 + HMAC_SIZE..4 + HMAC_SIZE + IV_SIZE];
    let enc_session_blob =
        &data[4 + HMAC_SIZE + IV_SIZE..4 + HMAC_SIZE + IV_SIZE + ENC_SESSION_BLOB_SIZE];
    let ciphertext = &data[4 + HMAC_SIZE + IV_SIZE + ENC_SESSION_BLOB_SIZE..];

    // Verify HMAC-SHA256 of (master_iv + enc_session_blob + ciphertext) using key[1]
    let hmac_key = &keys.keys[1];
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(hmac_key).context("HMAC key[1] init failed")?;
    mac.update(master_iv);
    mac.update(enc_session_blob);
    mac.update(ciphertext);
    mac.verify_slice(stored_hmac)
        .map_err(|_| anyhow::anyhow!("ARQO HMAC verification failed"))?;

    // Decrypt enc_session_blob using key[0] and master_iv to get (data_iv || session_key)
    let enc_key = &keys.keys[0];
    let aes_key = if enc_key.len() >= 32 {
        &enc_key[..32]
    } else {
        bail!("enc key too short")
    };
    let mut session_buf = enc_session_blob.to_vec();
    let session_plain = cbc::Decryptor::<Aes256>::new_from_slices(aes_key, master_iv)
        .context("AES init failed for session key")?
        .decrypt_padded_mut::<Pkcs7>(&mut session_buf)
        .map_err(|e| anyhow::anyhow!("PKCS7 unpad failed for session blob: {e:?}"))?;

    // session_plain = data_iv(16) + session_key(32)
    if session_plain.len() < IV_SIZE + 32 {
        bail!(
            "session blob plaintext too short: {} bytes",
            session_plain.len()
        );
    }
    let data_iv = &session_plain[..IV_SIZE];
    let session_key = &session_plain[IV_SIZE..IV_SIZE + 32];

    // Decrypt ciphertext in place using session_key and data_iv. The plaintext
    // is a prefix of `buf`, so truncate instead of copying it out again.
    let mut buf = ciphertext.to_vec();
    let plain_len = cbc::Decryptor::<Aes256>::new_from_slices(session_key, data_iv)
        .context("AES init failed for data")?
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| anyhow::anyhow!("PKCS7 unpad failed for data: {e:?}"))?
        .len();
    buf.truncate(plain_len);
    Ok(buf)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Build an ARQO object for `plain` the way Arq 7 writes one.
    pub(crate) fn encrypt_arqo(plain: &[u8], keys: &Arq7Keys) -> Vec<u8> {
        use cbc::cipher::BlockEncryptMut;
        let master_iv = [3u8; IV_SIZE];
        let data_iv = [5u8; IV_SIZE];
        let session_key = [9u8; 32];
        let mut session = data_iv.to_vec();
        session.extend_from_slice(&session_key);
        let enc_session =
            cbc::Encryptor::<Aes256>::new_from_slices(&keys.keys[0][..32], &master_iv)
                .unwrap()
                .encrypt_padded_vec_mut::<Pkcs7>(&session);
        assert_eq!(enc_session.len(), ENC_SESSION_BLOB_SIZE);
        let ciphertext = cbc::Encryptor::<Aes256>::new_from_slices(&session_key, &data_iv)
            .unwrap()
            .encrypt_padded_vec_mut::<Pkcs7>(plain);
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&keys.keys[1]).unwrap();
        mac.update(&master_iv);
        mac.update(&enc_session);
        mac.update(&ciphertext);
        let mut out = ARQO_MAGIC.to_vec();
        out.extend_from_slice(&mac.finalize().into_bytes());
        out.extend_from_slice(&master_iv);
        out.extend_from_slice(&enc_session);
        out.extend_from_slice(&ciphertext);
        out
    }

    pub(crate) fn test_keys() -> Arq7Keys {
        Arq7Keys {
            keys: [vec![1u8; 64], vec![2u8; 64], vec![4u8; 32]],
        }
    }

    #[test]
    fn arqo_roundtrip_and_tamper_detected() {
        let keys = test_keys();
        for plain in [&b""[..], b"x", b"exactly sixteen!", &[7u8; 1000][..]] {
            let obj = encrypt_arqo(plain, &keys);
            assert_eq!(decrypt_arq7_object(&obj, &keys).unwrap(), plain);
        }
        let mut obj = encrypt_arqo(b"hello", &keys);
        let last = obj.len() - 1;
        obj[last] ^= 1;
        let err = decrypt_arq7_object(&obj, &keys).unwrap_err();
        assert!(format!("{err:#}").contains("HMAC"));
    }

    #[test]
    fn bad_header_rejected() {
        assert!(Arq7Keys::from_dat(b"WRONG", "password").is_err());
    }

    #[test]
    fn short_object_rejected() {
        let keys = Arq7Keys {
            keys: [vec![0u8; 64], vec![0u8; 64], vec![0u8; 64]],
        };
        assert!(decrypt_arq7_object(&[0u8; 10], &keys).is_err());
    }

    #[test]
    fn non_arqo_rejected() {
        let keys = Arq7Keys {
            keys: [vec![0u8; 64], vec![0u8; 64], vec![0u8; 64]],
        };
        // Right length but wrong magic
        assert!(decrypt_arq7_object(&[0u8; 200], &keys).is_err());
    }
}

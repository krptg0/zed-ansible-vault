//! Native implementation of the ansible-vault `AES256` format (versions 1.1
//! and 1.2), byte-for-byte compatible with `ansible/parsing/vault/__init__.py`.

use std::fmt;

use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

pub const HEADER: &str = "$ANSIBLE_VAULT";
pub const DEFAULT_VAULT_ID: &str = "default";

const CIPHER: &str = "AES256";
const KDF_ITERATIONS: u32 = 10_000;
const KEY_LEN: usize = 32;
const IV_LEN: usize = 16;
const SALT_LEN: usize = 32;
const BLOCK_LEN: usize = 16;
const LINE_WIDTH: usize = 80;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// A vault password together with the vault id it is labelled with.
#[derive(Clone)]
pub struct Secret {
    pub vault_id: String,
    pub password: Vec<u8>,
}

impl Secret {
    pub fn new(vault_id: impl Into<String>, password: impl Into<Vec<u8>>) -> Self {
        Self {
            vault_id: vault_id.into(),
            password: password.into(),
        }
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret")
            .field("vault_id", &self.vault_id)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    NotVault,
    UnsupportedCipher(String),
    Format(String),
    /// No secret produced a valid HMAC.
    WrongPassword,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotVault => write!(f, "input is not vault encrypted data"),
            Self::UnsupportedCipher(name) => write!(f, "{name} cipher could not be found"),
            Self::Format(detail) => write!(f, "vault format error: {detail}"),
            Self::WrongPassword => {
                write!(
                    f,
                    "decryption failed: HMAC verification failed (wrong vault password?)"
                )
            }
        }
    }
}

impl std::error::Error for VaultError {}

/// Result of a successful decryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decrypted {
    pub plaintext: Vec<u8>,
    pub version: String,
    /// Vault id from a 1.2 header, if any.
    pub vault_id: Option<String>,
}

/// Header fields and decoded payload of a vault envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Envelope {
    version: String,
    vault_id: Option<String>,
    salt: Vec<u8>,
    hmac: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// True when `text` starts with the vault header, as Ansible's `is_encrypted`.
pub fn is_vault(text: &str) -> bool {
    text.starts_with(HEADER)
}

/// Encrypts `plaintext` with a fresh random salt. The envelope ends with `\n`.
pub fn encrypt(plaintext: &[u8], secret: &Secret) -> String {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).expect("OS random generator unavailable");
    encrypt_with_salt(plaintext, secret, &salt)
}

fn encrypt_with_salt(plaintext: &[u8], secret: &Secret, salt: &[u8]) -> String {
    let (key1, key2, iv) = derive_keys(&secret.password, salt);

    let mut ciphertext = pkcs7_pad(plaintext);
    Aes256Ctr::new_from_slices(&key1, &iv)
        .expect("key and iv lengths are fixed")
        .apply_keystream(&mut ciphertext);

    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(&key2).expect("HMAC accepts any key length");
    mac.update(&ciphertext);
    let hmac = mac.finalize().into_bytes();

    let inner = format!(
        "{}\n{}\n{}",
        hex::encode(salt),
        hex::encode(hmac),
        hex::encode(&ciphertext)
    );
    let body = hex::encode(inner);

    let mut out = header(&secret.vault_id);
    for chunk in body.as_bytes().chunks(LINE_WIDTH) {
        out.push('\n');
        out.push_str(std::str::from_utf8(chunk).expect("hex is ASCII"));
    }
    out.push('\n');
    out
}

fn header(vault_id: &str) -> String {
    if vault_id.is_empty() || vault_id == DEFAULT_VAULT_ID {
        format!("{HEADER};1.1;{CIPHER}")
    } else {
        format!("{HEADER};1.2;{CIPHER};{vault_id}")
    }
}

/// Decrypts an envelope, trying the secret whose id matches the header first,
/// then every other secret (Ansible's default with `vault_id_match = False`).
///
/// More tolerant than Ansible on layout: every line is trimmed, so indented
/// inline values and CRLF line endings decrypt as-is.
pub fn decrypt(text: &str, secrets: &[Secret]) -> Result<Decrypted, VaultError> {
    let envelope = parse_envelope(text)?;
    let (matching, others): (Vec<&Secret>, Vec<&Secret>) = secrets
        .iter()
        .partition(|s| envelope.vault_id.as_deref() == Some(s.vault_id.as_str()));

    for secret in matching.into_iter().chain(others) {
        if let Some(plaintext) = decrypt_with(&envelope, &secret.password)? {
            return Ok(Decrypted {
                plaintext,
                version: envelope.version.clone(),
                vault_id: envelope.vault_id.clone(),
            });
        }
    }
    Err(VaultError::WrongPassword)
}

/// `Ok(None)` when the HMAC does not match this password.
fn decrypt_with(envelope: &Envelope, password: &[u8]) -> Result<Option<Vec<u8>>, VaultError> {
    let (key1, key2, iv) = derive_keys(password, &envelope.salt);

    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(&key2).expect("HMAC accepts any key length");
    mac.update(&envelope.ciphertext);
    if mac.verify_slice(&envelope.hmac).is_err() {
        return Ok(None);
    }

    let mut plaintext = envelope.ciphertext.clone();
    Aes256Ctr::new_from_slices(&key1, &iv)
        .expect("key and iv lengths are fixed")
        .apply_keystream(&mut plaintext);
    pkcs7_unpad(&mut plaintext)?;
    Ok(Some(plaintext))
}

fn parse_envelope(text: &str) -> Result<Envelope, VaultError> {
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    let header = lines.next().ok_or(VaultError::NotVault)?;
    if !header.starts_with(HEADER) {
        return Err(VaultError::NotVault);
    }

    let parts: Vec<&str> = header.split(';').map(str::trim).collect();
    if parts.len() < 3 || parts[0] != HEADER {
        return Err(VaultError::Format(format!(
            "invalid vault header `{header}`"
        )));
    }
    let version = parts[1].to_string();
    if parts[2] != CIPHER {
        return Err(VaultError::UnsupportedCipher(parts[2].to_string()));
    }
    let vault_id = parts
        .get(3)
        .filter(|id| !id.is_empty())
        .map(|id| id.to_string());

    let body: String = lines.collect();
    let inner = unhex(&body)?;
    let mut fields = inner.splitn(3, |&b| b == b'\n');
    let (Some(salt), Some(hmac), Some(ciphertext)) = (fields.next(), fields.next(), fields.next())
    else {
        return Err(VaultError::Format(
            "expected salt, hmac and ciphertext".into(),
        ));
    };

    Ok(Envelope {
        version,
        vault_id,
        salt: unhex_bytes(salt)?,
        hmac: unhex_bytes(hmac)?,
        ciphertext: unhex_bytes(ciphertext)?,
    })
}

fn unhex(text: &str) -> Result<Vec<u8>, VaultError> {
    hex::decode(text).map_err(|e| VaultError::Format(format!("unhexlify error: {e}")))
}

fn unhex_bytes(bytes: &[u8]) -> Result<Vec<u8>, VaultError> {
    hex::decode(bytes).map_err(|e| VaultError::Format(format!("unhexlify error: {e}")))
}

fn derive_keys(password: &[u8], salt: &[u8]) -> ([u8; KEY_LEN], [u8; KEY_LEN], [u8; IV_LEN]) {
    let mut derived = [0u8; 2 * KEY_LEN + IV_LEN];
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, KDF_ITERATIONS, &mut derived);
    let mut key1 = [0u8; KEY_LEN];
    let mut key2 = [0u8; KEY_LEN];
    let mut iv = [0u8; IV_LEN];
    key1.copy_from_slice(&derived[..KEY_LEN]);
    key2.copy_from_slice(&derived[KEY_LEN..2 * KEY_LEN]);
    iv.copy_from_slice(&derived[2 * KEY_LEN..]);
    (key1, key2, iv)
}

fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
    let pad = BLOCK_LEN - data.len() % BLOCK_LEN;
    let mut out = Vec::with_capacity(data.len() + pad);
    out.extend_from_slice(data);
    out.resize(data.len() + pad, pad as u8);
    out
}

fn pkcs7_unpad(data: &mut Vec<u8>) -> Result<(), VaultError> {
    let invalid = || VaultError::Format("invalid padding bytes".into());
    let pad = *data.last().ok_or_else(invalid)? as usize;
    if pad == 0 || pad > BLOCK_LEN || pad > data.len() || !data.len().is_multiple_of(BLOCK_LEN) {
        return Err(invalid());
    }
    if !data[data.len() - pad..].iter().all(|&b| b as usize == pad) {
        return Err(invalid());
    }
    data.truncate(data.len() - pad);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "test-password-123";

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
    }

    fn secret() -> Secret {
        Secret::new(DEFAULT_VAULT_ID, PASSWORD)
    }

    fn decrypt_str(text: &str) -> String {
        String::from_utf8(decrypt(text, &[secret()]).unwrap().plaintext).unwrap()
    }

    /// Produced by Ansible's own `VaultAES256.encrypt(b'hello', secret, salt=bytes(range(32)))`.
    const KNOWN_ANSWER: &str = "$ANSIBLE_VAULT;1.1;AES256
30303031303230333034303530363037303830393061306230633064306530663130313131323133
3134313531363137313831393161316231633164316531660a303636653438313662396566646631
33633137643834396533653430313666663861333231643530326566396430633562363639646230
3137653230633237330a383532653766336234636562336361643961616538633735386530653263
6264
";

    #[test]
    fn encrypt_matches_ansible_known_answer() {
        let salt: Vec<u8> = (0..32).collect();
        assert_eq!(encrypt_with_salt(b"hello", &secret(), &salt), KNOWN_ANSWER);
    }

    #[test]
    fn decrypts_known_answer() {
        assert_eq!(decrypt_str(KNOWN_ANSWER), "hello");
    }

    #[test]
    fn decrypts_ansible_vault_fixtures() {
        assert_eq!(decrypt_str(&fixture("hello.vault")), "hello");
        assert_eq!(
            decrypt_str(&fixture("file.vault")),
            "api_token: abc123\nport: 8080\n"
        );
        assert_eq!(decrypt_str(&fixture("utf8.vault")), "pässwörd €🔑");
    }

    #[test]
    fn decrypts_1_2_header_and_reports_vault_id() {
        let decrypted = decrypt(&fixture("dev_id.vault"), &[secret()]).unwrap();
        assert_eq!(decrypted.plaintext, b"hello");
        assert_eq!(decrypted.version, "1.2");
        assert_eq!(decrypted.vault_id.as_deref(), Some("dev"));
    }

    #[test]
    fn matching_vault_id_is_tried_first_then_others() {
        let wrong = Secret::new("prod", "nope");
        let right = Secret::new("other", PASSWORD);
        let decrypted = decrypt(&fixture("dev_id.vault"), &[wrong, right]).unwrap();
        assert_eq!(decrypted.plaintext, b"hello");
    }

    #[test]
    fn round_trip_with_random_salt() {
        for plaintext in [
            "",
            "x",
            "exactly16bytes!!",
            "multi\nline\nvalue\n",
            "pässwörd €🔑",
        ] {
            let envelope = encrypt(plaintext.as_bytes(), &secret());
            assert!(envelope.ends_with('\n'));
            assert!(envelope
                .lines()
                .skip(1)
                .all(|line| line.len() <= LINE_WIDTH));
            assert_eq!(decrypt_str(&envelope), plaintext);
        }
    }

    #[test]
    fn non_default_vault_id_uses_1_2_header() {
        let envelope = encrypt(b"hello", &Secret::new("dev", PASSWORD));
        assert!(envelope.starts_with("$ANSIBLE_VAULT;1.2;AES256;dev\n"));
    }

    #[test]
    fn tolerates_indentation_crlf_and_uppercase_hex() {
        let indented: String = KNOWN_ANSWER
            .lines()
            .map(|l| format!("          {l}  \r\n"))
            .collect();
        assert_eq!(decrypt_str(&indented), "hello");
        let upper: String = KNOWN_ANSWER
            .lines()
            .enumerate()
            .map(|(i, l)| {
                if i == 0 {
                    format!("{l}\n")
                } else {
                    format!("{}\n", l.to_uppercase())
                }
            })
            .collect();
        assert_eq!(decrypt_str(&upper), "hello");
    }

    #[test]
    fn wrong_password_is_reported() {
        let err = decrypt(KNOWN_ANSWER, &[Secret::new(DEFAULT_VAULT_ID, "bad")]).unwrap_err();
        assert_eq!(err, VaultError::WrongPassword);
    }

    #[test]
    fn tampered_ciphertext_fails_hmac() {
        let tampered = KNOWN_ANSWER.replacen("6264", "6265", 1);
        assert_eq!(
            decrypt(&tampered, &[secret()]).unwrap_err(),
            VaultError::WrongPassword
        );
    }

    #[test]
    fn rejects_non_vault_and_unknown_cipher() {
        assert_eq!(
            decrypt("hello", &[secret()]).unwrap_err(),
            VaultError::NotVault
        );
        let lowercase = KNOWN_ANSWER.replacen("AES256", "aes256", 1);
        assert_eq!(
            decrypt(&lowercase, &[secret()]).unwrap_err(),
            VaultError::UnsupportedCipher("aes256".into())
        );
    }

    #[test]
    fn rejects_bad_hex() {
        let broken = KNOWN_ANSWER.replacen("6264", "62zz", 1);
        assert!(matches!(
            decrypt(&broken, &[secret()]),
            Err(VaultError::Format(_))
        ));
    }

    #[test]
    fn secret_debug_never_prints_password() {
        assert!(!format!("{:?}", secret()).contains(PASSWORD));
    }
}

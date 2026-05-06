//! Small facade over real cryptographic primitives.
//!
//! Callers pass semantic context and canonical bytes into this facade.
//! The facade owns primitive selection and low-level library calls, keeping
//! event modules from growing their own hash or signature implementations.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

pub const HASH_BYTES: usize = 32;
pub const ED25519_PRIVATE_KEY_BYTES: usize = 32;
pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;
pub const ED25519_SIGNATURE_BYTES: usize = 64;
pub const X25519_PRIVATE_KEY_BYTES: usize = 32;
pub const X25519_PUBLIC_KEY_BYTES: usize = 32;
pub const XCHACHA20_POLY1305_NONCE_BYTES: usize = 24;

pub type Hash = [u8; HASH_BYTES];
pub type Ed25519PrivateKey = [u8; ED25519_PRIVATE_KEY_BYTES];
pub type Ed25519PublicKey = [u8; ED25519_PUBLIC_KEY_BYTES];
pub type Ed25519Signature = [u8; ED25519_SIGNATURE_BYTES];
pub type X25519PrivateKey = [u8; X25519_PRIVATE_KEY_BYTES];
pub type X25519PublicKey = [u8; X25519_PUBLIC_KEY_BYTES];
pub type XChaCha20Poly1305Nonce = [u8; XCHACHA20_POLY1305_NONCE_BYTES];

pub fn hash(bytes: &[u8]) -> Hash {
    *blake3::hash(bytes).as_bytes()
}

pub fn random_bytes_32() -> [u8; 32] {
    let mut out = [0; 32];
    OsRng.fill_bytes(&mut out);
    out
}

pub fn ed25519_public_key(private_key: &Ed25519PrivateKey) -> Ed25519PublicKey {
    VerifyingKey::from(&SigningKey::from_bytes(private_key)).to_bytes()
}

pub fn random_ed25519_private_key() -> Ed25519PrivateKey {
    random_bytes_32()
}

pub fn ed25519_sign(private_key: &Ed25519PrivateKey, bytes: &[u8]) -> Ed25519Signature {
    SigningKey::from_bytes(private_key).sign(bytes).to_bytes()
}

pub fn ed25519_verify(
    public_key: &Ed25519PublicKey,
    bytes: &[u8],
    signature: &Ed25519Signature,
) -> bool {
    let Ok(public_key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let signature = Signature::from_bytes(signature);
    public_key.verify(bytes, &signature).is_ok()
}

pub fn random_x25519_private_key() -> X25519PrivateKey {
    X25519Secret::random_from_rng(OsRng).to_bytes()
}

pub fn x25519_public_key(private_key: &X25519PrivateKey) -> X25519PublicKey {
    X25519Public::from(&X25519Secret::from(*private_key)).to_bytes()
}

pub fn random_xchacha20poly1305_nonce() -> XChaCha20Poly1305Nonce {
    let mut nonce = [0; XCHACHA20_POLY1305_NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn x25519_xchacha20poly1305_encrypt(
    local_secret: &X25519PrivateKey,
    remote_public_key: &X25519PublicKey,
    purpose: &[u8],
    associated_data: &[u8],
    nonce: &XChaCha20Poly1305Nonce,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let key = x25519_hkdf_sha256_key(local_secret, remote_public_key, purpose)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| "encrypt x25519 xchacha20poly1305 payload".to_string())
}

pub fn x25519_xchacha20poly1305_decrypt(
    local_secret: &X25519PrivateKey,
    remote_public_key: &X25519PublicKey,
    purpose: &[u8],
    associated_data: &[u8],
    nonce: &XChaCha20Poly1305Nonce,
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let key = x25519_hkdf_sha256_key(local_secret, remote_public_key, purpose)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| "decrypt x25519 xchacha20poly1305 payload".to_string())
}

fn x25519_hkdf_sha256_key(
    local_secret: &X25519PrivateKey,
    remote_public_key: &X25519PublicKey,
    purpose: &[u8],
) -> Result<[u8; 32], String> {
    let secret = X25519Secret::from(*local_secret);
    let remote = X25519Public::from(*remote_public_key);
    let shared = secret.diffie_hellman(&remote);
    let hkdf = Hkdf::<Sha256>::new(Some(purpose), shared.as_bytes());
    let mut key = [0; 32];
    hkdf.expand(b"topo x25519 xchacha20poly1305 key", &mut key)
        .map_err(|_| "derive x25519 xchacha20poly1305 key".to_string())?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Invariant: hash is deterministic and input sensitive.
    #[test]
    fn hash_is_deterministic_and_input_sensitive() {
        let left = hash(b"topo auth graph");
        assert_eq!(left, hash(b"topo auth graph"));
        assert_ne!(left, hash(b"topo auth graph."));
    }

    // Invariant: ed25519 signatures verify with matching key and bytes.
    #[test]
    fn ed25519_signatures_verify_with_matching_key_and_bytes() {
        let private_key = [7; ED25519_PRIVATE_KEY_BYTES];
        let public_key = ed25519_public_key(&private_key);
        let bytes = b"canonical signed envelope bytes";

        let signature = ed25519_sign(&private_key, bytes);

        assert!(ed25519_verify(&public_key, bytes, &signature));
        assert!(!ed25519_verify(&public_key, b"changed bytes", &signature));
        assert!(!ed25519_verify(
            &ed25519_public_key(&[8; ED25519_PRIVATE_KEY_BYTES]),
            bytes,
            &signature
        ));
    }

    // Invariant: ed25519 signatures are deterministic for the same key and bytes.
    #[test]
    fn ed25519_signatures_are_deterministic_for_the_same_key_and_bytes() {
        let private_key = [11; ED25519_PRIVATE_KEY_BYTES];
        let bytes = b"fixed canonical bytes";

        assert_eq!(
            ed25519_sign(&private_key, bytes),
            ed25519_sign(&private_key, bytes)
        );
    }

    // Invariant: x25519 xchacha20poly1305 roundtrips with matching context.
    #[test]
    fn x25519_xchacha20poly1305_roundtrips_with_matching_context() {
        let alice_secret = random_x25519_private_key();
        let alice_public = x25519_public_key(&alice_secret);
        let bob_secret = random_x25519_private_key();
        let bob_public = x25519_public_key(&bob_secret);
        let nonce = random_xchacha20poly1305_nonce();
        let purpose = b"test-purpose";
        let aad = b"test-aad";
        let plaintext = b"secret payload";

        let ciphertext = x25519_xchacha20poly1305_encrypt(
            &alice_secret,
            &bob_public,
            purpose,
            aad,
            &nonce,
            plaintext,
        )
        .expect("encrypt");
        let decrypted = x25519_xchacha20poly1305_decrypt(
            &bob_secret,
            &alice_public,
            purpose,
            aad,
            &nonce,
            &ciphertext,
        )
        .expect("decrypt");

        assert_eq!(decrypted, plaintext);
        assert!(x25519_xchacha20poly1305_decrypt(
            &bob_secret,
            &alice_public,
            b"wrong-purpose",
            aad,
            &nonce,
            &ciphertext,
        )
        .is_err());
        assert!(x25519_xchacha20poly1305_decrypt(
            &bob_secret,
            &alice_public,
            purpose,
            b"wrong-aad",
            &nonce,
            &ciphertext,
        )
        .is_err());
    }
}

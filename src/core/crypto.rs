//! Small facade over real cryptographic primitives.
//!
//! Callers pass semantic context and canonical bytes into this facade.
//! The facade owns primitive selection and low-level library calls, keeping
//! event modules from growing their own hash or signature implementations.

use std::io::{Cursor, Read, Write};

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
pub const XCHACHA20_POLY1305_KEY_BYTES: usize = 32;
pub const XCHACHA20_POLY1305_NONCE_BYTES: usize = 24;
pub const XCHACHA20_POLY1305_TAG_BYTES: usize = 16;

pub type Hash = [u8; HASH_BYTES];
pub type Ed25519PrivateKey = [u8; ED25519_PRIVATE_KEY_BYTES];
pub type Ed25519PublicKey = [u8; ED25519_PUBLIC_KEY_BYTES];
pub type Ed25519Signature = [u8; ED25519_SIGNATURE_BYTES];
pub type X25519PrivateKey = [u8; X25519_PRIVATE_KEY_BYTES];
pub type X25519PublicKey = [u8; X25519_PUBLIC_KEY_BYTES];
pub type XChaCha20Poly1305Key = [u8; XCHACHA20_POLY1305_KEY_BYTES];
pub type XChaCha20Poly1305Nonce = [u8; XCHACHA20_POLY1305_NONCE_BYTES];

pub fn hash(bytes: &[u8]) -> Hash {
    *blake3::hash(bytes).as_bytes()
}

/// BLAKE3 keyed-hash with explicit domain separation.
///
/// `key` is the 32-byte parent secret (BLAKE3 keyed-hash takes a 32-byte key).
/// `domain` is a fixed ASCII tag prefixing the input; pick one tag per
/// distinct derivation purpose so two purposes can share the same key without
/// colliding. `info` is the variable-length per-input data appended after the
/// domain tag.
///
/// This is BLAKE3's published keyed-hash mode (`blake3::keyed_hash`), not a
/// home-grown KDF. Two callers passing the same `(key, domain, info)` triple
/// produce the same 32-byte output; changing any byte of any input changes
/// the output.
pub fn blake3_keyed_hash(key: &[u8; HASH_BYTES], domain: &[u8], info: &[u8]) -> [u8; HASH_BYTES] {
    let mut input = Vec::with_capacity(domain.len() + 1 + info.len());
    input.extend_from_slice(domain);
    input.push(0);
    input.extend_from_slice(info);
    *blake3::keyed_hash(key, &input).as_bytes()
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

pub fn x25519_diffie_hellman(
    local_secret: &X25519PrivateKey,
    remote_public_key: &X25519PublicKey,
) -> [u8; 32] {
    let secret = X25519Secret::from(*local_secret);
    let remote = X25519Public::from(*remote_public_key);
    *secret.diffie_hellman(&remote).as_bytes()
}

pub fn random_xchacha20poly1305_nonce() -> XChaCha20Poly1305Nonce {
    let mut nonce = [0; XCHACHA20_POLY1305_NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn random_xchacha20poly1305_key() -> XChaCha20Poly1305Key {
    random_bytes_32()
}

pub fn hkdf_sha256_key(
    input_key_material: &[u8],
    purpose: &[u8],
    associated_data: &[u8],
) -> Result<XChaCha20Poly1305Key, String> {
    let hkdf = Hkdf::<Sha256>::new(Some(purpose), input_key_material);
    let mut key = [0; XCHACHA20_POLY1305_KEY_BYTES];
    hkdf.expand(associated_data, &mut key)
        .map_err(|_| "derive hkdf sha256 key".to_string())?;
    Ok(key)
}

pub fn xchacha20poly1305_encrypt(
    key: &XChaCha20Poly1305Key,
    associated_data: &[u8],
    nonce: &XChaCha20Poly1305Nonce,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| "encrypt xchacha20poly1305 payload".to_string())
}

pub fn xchacha20poly1305_decrypt(
    key: &XChaCha20Poly1305Key,
    associated_data: &[u8],
    nonce: &XChaCha20Poly1305Nonce,
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| "decrypt xchacha20poly1305 payload".to_string())
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
    let shared = x25519_diffie_hellman(local_secret, remote_public_key);
    let hkdf = Hkdf::<Sha256>::new(Some(purpose), &shared);
    let mut key = [0; 32];
    hkdf.expand(b"topo x25519 xchacha20poly1305 key", &mut key)
        .map_err(|_| "derive x25519 xchacha20poly1305 key".to_string())?;
    Ok(key)
}

/// BLAKE3 verified streaming root hash + outboard for the given plaintext.
///
/// The outboard carries the BLAKE3 tree nodes that prove any slice of the
/// plaintext belongs to the returned root hash. Senders compute this once;
/// receivers verify each slice independently against the root.
pub fn bao_outboard(plaintext: &[u8]) -> Result<(Hash, Vec<u8>), String> {
    let mut outboard = Vec::new();
    let mut encoder = bao::encode::Encoder::new_outboard(Cursor::new(&mut outboard));
    encoder
        .write_all(plaintext)
        .map_err(|err| format!("bao encode: {err}"))?;
    let hash = encoder
        .finalize()
        .map_err(|err| format!("bao finalize: {err}"))?;
    Ok((*hash.as_bytes(), outboard))
}

/// Extract a self-contained BAO slice proof for `[slice_start, slice_start + slice_len)`.
///
/// The returned bytes contain both the verified plaintext and the tree nodes
/// needed to verify it against `root_hash`. They are what slice events should
/// carry on the wire.
pub fn bao_extract_slice(
    plaintext: &[u8],
    outboard: &[u8],
    slice_start: u64,
    slice_len: u64,
) -> Result<Vec<u8>, String> {
    let mut extractor = bao::encode::SliceExtractor::new_outboard(
        Cursor::new(plaintext),
        Cursor::new(outboard),
        slice_start,
        slice_len,
    );
    let mut proof = Vec::new();
    extractor
        .read_to_end(&mut proof)
        .map_err(|err| format!("bao extract: {err}"))?;
    Ok(proof)
}

/// Verify a BAO slice proof against `root_hash` and return the slice plaintext.
pub fn bao_verify_slice(
    root_hash: &Hash,
    proof: &[u8],
    slice_start: u64,
    slice_len: u64,
) -> Result<Vec<u8>, String> {
    let hash = bao::Hash::from(*root_hash);
    let mut decoder =
        bao::decode::SliceDecoder::new(Cursor::new(proof), &hash, slice_start, slice_len);
    let mut output = Vec::new();
    decoder
        .read_to_end(&mut output)
        .map_err(|err| format!("bao verify: {err}"))?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic_and_input_sensitive() {
        let left = hash(b"topo auth graph");
        assert_eq!(left, hash(b"topo auth graph"));
        assert_ne!(left, hash(b"topo auth graph."));
    }

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

    #[test]
    fn ed25519_signatures_are_deterministic_for_the_same_key_and_bytes() {
        let private_key = [11; ED25519_PRIVATE_KEY_BYTES];
        let bytes = b"fixed canonical bytes";

        assert_eq!(
            ed25519_sign(&private_key, bytes),
            ed25519_sign(&private_key, bytes)
        );
    }

    #[test]
    fn xchacha20poly1305_roundtrips_and_rejects_tamper() {
        let key = random_xchacha20poly1305_key();
        let nonce = random_xchacha20poly1305_nonce();
        let aad = b"topo test symmetric aad";
        let plaintext = b"phase-one local epoch secret bytes";

        let ciphertext = xchacha20poly1305_encrypt(&key, aad, &nonce, plaintext).expect("encrypt");

        assert_eq!(
            xchacha20poly1305_decrypt(&key, aad, &nonce, &ciphertext).expect("decrypt"),
            plaintext
        );
        assert!(xchacha20poly1305_decrypt(
            &random_xchacha20poly1305_key(),
            aad,
            &nonce,
            &ciphertext
        )
        .is_err());
        assert!(xchacha20poly1305_decrypt(&key, b"wrong aad", &nonce, &ciphertext).is_err());

        let mut tampered_nonce = nonce;
        tampered_nonce[0] ^= 1;
        assert!(xchacha20poly1305_decrypt(&key, aad, &tampered_nonce, &ciphertext).is_err());

        let mut tampered_ciphertext = ciphertext;
        tampered_ciphertext[0] ^= 1;
        assert!(xchacha20poly1305_decrypt(&key, aad, &nonce, &tampered_ciphertext).is_err());
    }

    #[test]
    fn blake3_keyed_hash_is_deterministic_and_context_bound() {
        let key = [3; HASH_BYTES];
        let domain = b"topo test domain v1";
        let info = b"some+associated+data";

        let left = blake3_keyed_hash(&key, domain, info);
        let right = blake3_keyed_hash(&key, domain, info);
        let other_key = blake3_keyed_hash(&[4; HASH_BYTES], domain, info);
        let other_domain = blake3_keyed_hash(&key, b"topo test domain v2", info);
        let other_info = blake3_keyed_hash(&key, domain, b"different info");

        assert_eq!(left, right);
        assert_ne!(left, other_key);
        assert_ne!(left, other_domain);
        assert_ne!(left, other_info);
    }

    #[test]
    fn hkdf_sha256_key_is_deterministic_and_context_bound() {
        let input = [7; 32];
        let purpose = b"test-purpose";
        let associated_data = b"test-associated-data";

        let left = hkdf_sha256_key(&input, purpose, associated_data).expect("derive");
        let right = hkdf_sha256_key(&input, purpose, associated_data).expect("derive");
        let wrong_purpose =
            hkdf_sha256_key(&input, b"other-purpose", associated_data).expect("derive");
        let wrong_data = hkdf_sha256_key(&input, purpose, b"other-data").expect("derive");

        assert_eq!(left, right);
        assert_ne!(left, wrong_purpose);
        assert_ne!(left, wrong_data);
    }

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

    #[test]
    fn bao_round_trips_each_slice_against_root_hash() {
        let plaintext: Vec<u8> = (0..600_000u32).map(|byte| byte as u8).collect();
        let (root_hash, outboard) = bao_outboard(&plaintext).expect("outboard");

        let slice_size = 256 * 1024;
        let mut start = 0u64;
        while (start as usize) < plaintext.len() {
            let len = (plaintext.len() as u64 - start).min(slice_size as u64);
            let proof =
                bao_extract_slice(&plaintext, &outboard, start, len).expect("extract slice");
            let verified = bao_verify_slice(&root_hash, &proof, start, len).expect("verify slice");
            assert_eq!(
                verified.as_slice(),
                &plaintext[start as usize..(start + len) as usize]
            );
            start += slice_size as u64;
        }
    }

    #[test]
    fn bao_verify_rejects_tampered_proof_and_wrong_root_hash() {
        let plaintext = b"important payload bytes".to_vec();
        let (root_hash, outboard) = bao_outboard(&plaintext).expect("outboard");
        let mut proof = bao_extract_slice(&plaintext, &outboard, 0, plaintext.len() as u64)
            .expect("extract slice");

        let last = proof.len() - 1;
        proof[last] ^= 1;
        assert!(bao_verify_slice(&root_hash, &proof, 0, plaintext.len() as u64).is_err());

        proof[last] ^= 1;
        let wrong_hash = [0xff; HASH_BYTES];
        assert!(bao_verify_slice(&wrong_hash, &proof, 0, plaintext.len() as u64).is_err());
    }
}

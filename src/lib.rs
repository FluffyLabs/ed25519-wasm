//#![cfg_attr(not(feature = "std"), no_std)]
use ed25519_dalek::{VerifyingKey, Signature};
use wasm_bindgen::prelude::wasm_bindgen;


#[wasm_bindgen]
pub fn verify_ed25519(
    data: &[u8], // [key (32 bytes), signature (64 bytes), message (? bytes); item_length]
    item_length: usize,
) -> Vec<u8> {
    let results = data.chunks(item_length).map(|chunk| {
        let maybe_key = &chunk[0..32].try_into();
        let maybe_signature = &chunk[32..96].try_into();

        if maybe_key.is_err() || maybe_signature.is_err() {
            return 0;
        }

        let key = maybe_key.unwrap();
        let signature = maybe_signature.unwrap();
        let message = &chunk[96..];
        let verifying_key: VerifyingKey = VerifyingKey::from_bytes(key).unwrap();
        
        let verification_result = verifying_key.verify_strict(message, &Signature::from_bytes(&signature));

        if verification_result.is_ok() { 1 } else { 0 }
    }).collect();

    results
}

#[wasm_bindgen]
pub fn verify_ed25519_batch(
    data: &[u8], // [key (32 bytes), signature (64 bytes), message (? bytes); item_length]
    item_length: usize,
) -> bool {
    let chunks = data.chunks(item_length);

    let mut messages = vec![];
    let mut signatures = vec![];
    let mut keys = vec![];

    for chunk in chunks {
        let maybe_key = &chunk[0..32].try_into();
        let maybe_signature = &chunk[32..96].try_into();

        if maybe_key.is_err() || maybe_signature.is_err() {
            return false;
        }

        let key = maybe_key.unwrap();
        let signature = maybe_signature.unwrap();
        let message = &chunk[96..];
        let verifying_key: VerifyingKey = VerifyingKey::from_bytes(key).unwrap();
        messages.push(message);
        signatures.push(Signature::from_bytes(&signature));
        keys.push(verifying_key);
    }

    match ed25519_dalek::verify_batch(&messages, &signatures, &keys) {
        Ok(_) => true,
        Err(_) => false,
    }
}

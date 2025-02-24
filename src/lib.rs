use ed25519_dalek::{Signature, VerifyingKey};
use std::io::{Cursor, Read, Result};
use wasm_bindgen::prelude::wasm_bindgen;

/**
 * Verify Ed25519 signatures one by one using strict verification.
 *
 * This function is slower but does strict verification.
 */
#[wasm_bindgen]
pub fn verify_ed25519(
    data: &[u8], // [key (32 bytes), signature (64 bytes), message_length (1 byte), message ({message_length} bytes)]
) -> Vec<u8> {
    let mut results = vec![];
    let mut cursor = Cursor::new(data);

    while cursor.position() < data.len() as u64 {
        let maybe_key = read_key(&mut cursor);
        let maybe_signature = read_signature(&mut cursor);
        let maybe_message_length = read_message_length(&mut cursor);

        let (maybe_verifying_key, signature, message_len) =
            match (maybe_key, maybe_signature, maybe_message_length) {
                (Ok(key), Ok(signature), Ok(message_len)) => {
                    (VerifyingKey::from_bytes(&key), signature, message_len)
                }
                (_, Err(e), _) => {
                    println!("pppp, {}", e);
                    results.push(0);
                    continue;
                }
                _ => {
                    println!("ttt");
                    results.push(0);
                    continue;
                }
            };

        let maybe_message = read_message(&mut cursor, message_len as usize);
        let (verifying_key, message) = match (maybe_verifying_key, maybe_message) {
            (Ok(key), Ok(message)) => (key, message),
            _ => {
                println!("");
                results.push(0);
                continue;
            }
        };

        let verification_result: u8 =
            match verifying_key.verify_strict(&message, &Signature::from_bytes(&signature)) {
                Ok(_) => 1,
                Err(_) => 0,
            };

        results.push(verification_result);
    }

    results
}

/**
 * Verify Ed25519 signatures using build-in batch verification.
 *
 * This function is faster but does not do strict verification.
 * See https://crates.io/crates/ed25519-dalek#batch-verification for more information.
 */
#[wasm_bindgen]
pub fn verify_ed25519_batch(
    data: &[u8], // [key (32 bytes), signature (64 bytes), message_length (1 byte) message (message_length bytes)]
) -> bool {
    let mut cursor = Cursor::new(data);
    let mut messages = vec![];
    let mut signatures = vec![];
    let mut keys = vec![];
    while cursor.position() < data.len() as u64 {
        let maybe_key = read_key(&mut cursor);
        let maybe_signature = read_signature(&mut cursor);
        let maybe_message_length = read_message_length(&mut cursor);

        let (maybe_verifying_key, signature, message_len) =
            match (maybe_key, maybe_signature, maybe_message_length) {
                (Ok(key), Ok(signature), Ok(message_len)) => {
                    (VerifyingKey::from_bytes(&key), signature, message_len)
                }
                _ => {
                    continue;
                }
            };

        let maybe_message = read_message(&mut cursor, message_len as usize);
        let (verifying_key, message) = match (maybe_verifying_key, maybe_message) {
            (Ok(key), Ok(message)) => (key, message),
            _ => {
                continue;
            }
        };

        messages.push(message);
        signatures.push(Signature::from_bytes(&signature));
        keys.push(verifying_key);
    }

    let messages_refs: Vec<&[u8]> = messages.iter().map(|msg| msg.as_slice()).collect();
    match ed25519_dalek::verify_batch(&messages_refs, &signatures, &keys) {
        Ok(_) => true,
        Err(_) => false,
    }
}

const KEY_LENGTH: usize = 32;
const SIGNATURE_LENGTH: usize = 64;

fn read_key(cursor: &mut Cursor<&[u8]>) -> Result<[u8; KEY_LENGTH]> {
    let mut buf = [0u8; KEY_LENGTH];
    cursor.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_signature(cursor: &mut Cursor<&[u8]>) -> Result<[u8; SIGNATURE_LENGTH]> {
    let mut buf = [0u8; SIGNATURE_LENGTH];
    cursor.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_message_length(cursor: &mut Cursor<&[u8]>) -> Result<u8> {
    let mut buf = [0u8; 1];
    cursor.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn read_message(cursor: &mut Cursor<&[u8]>, length: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; length];
    cursor.read_exact(&mut buf)?;
    Ok(buf)
}

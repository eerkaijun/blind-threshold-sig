//! This module implements the hash functions corresponding to the ciphersuite FROST(Ed25519, SHA-512).
//!
//! Source: https://www.rfc-editor.org/rfc/rfc9591.html#name-frosted25519-sha-512
#![allow(non_snake_case)]

use sha2::{Digest, Sha512};

pub const CONTEXT_STRING: &str = "FROST-ED25519-SHA512-v1";

pub fn H1(m: Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha512::new();

    hasher.update(CONTEXT_STRING);
    hasher.update(b"rho");
    hasher.update(m);

    let output = hasher.finalize();
    output.to_vec()
}

pub fn H2(m: Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha512::new();

    hasher.update(m);

    let output = hasher.finalize();
    output.to_vec()
}

pub fn H3(m: Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha512::new();

    hasher.update(CONTEXT_STRING);
    hasher.update(b"nonce");
    hasher.update(m);

    let output = hasher.finalize();
    output.to_vec()
}

pub fn H4(m: Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha512::new();

    hasher.update(CONTEXT_STRING);
    hasher.update(b"msg");
    hasher.update(m);

    let output = hasher.finalize();
    output.to_vec()
}

pub fn H5(m: Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha512::new();

    hasher.update(CONTEXT_STRING);
    hasher.update(b"com");
    hasher.update(m);

    let output = hasher.finalize();
    output.to_vec()
}

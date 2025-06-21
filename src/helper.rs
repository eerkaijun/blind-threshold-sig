use ark_ec::AdditiveGroup;
use ark_ed25519::{EdwardsProjective as Element, Fr as ScalarField};
use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalSerialize;
use rand::RngCore;

use crate::ciphersuite::{H1, H2, H3, H4, H5};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonZeroScalar(ScalarField);

impl NonZeroScalar {
    pub fn new(value: ScalarField) -> Self {
        if value == ScalarField::ZERO {
            panic!("NonZeroScalar cannot be zero")
        }

        NonZeroScalar(value)
    }
}

/// A binding factor is a tuple of (identifier i, rho_i)
pub type BindingFactor = (NonZeroScalar, ScalarField);

/// A Commitment R_i is a tuple of (identifier i, D_i, E_i)
pub type Commitment = (NonZeroScalar, Element, Element);

pub fn nonce_generate(secret: ScalarField) -> ScalarField {
    // Generate a 32-byte random number
    let mut rng = rand::rng();
    let mut random_bytes = [0u8; 32];
    rng.fill_bytes(&mut random_bytes);

    let mut secret_bytes = Vec::with_capacity(32);
    secret
        .serialize_compressed(&mut secret_bytes)
        .expect("serialization failed");

    let mut message = Vec::with_capacity(64);
    message.extend_from_slice(&random_bytes);
    message.extend_from_slice(&secret_bytes);

    // return H3
    let hash_output = H3(message);
    ScalarField::from_le_bytes_mod_order(&hash_output)
}

/// Derives and returns a value used for polynomial interpolation.
///
/// # Panics
///
/// Panics if `x_coordinates` do not contain `x_i`, or if `x_i` is found more than once in
/// `x_coordinates`.
///
/// Reference: https://www.rfc-editor.org/rfc/rfc9591.html#section-4.2
pub fn derive_interpolating_value(
    x_coordinates: &[NonZeroScalar],
    x_i: NonZeroScalar,
) -> ScalarField {
    let mut numerator = ScalarField::ONE;
    let mut denominator = ScalarField::ONE;

    for x_j in x_coordinates {
        if x_j == &x_i {
            continue;
        }
        numerator *= x_j.0;
        denominator *= x_j.0 - x_i.0;
    }

    numerator / denominator
}

/// Encodes and returns a list of participant `Commitment`s into a byte string for use in the FROST
/// protocol, mostly for hashing purposes.
///
/// # Panics
///
/// Panics if serialization fails.
///
/// Reference: https://www.rfc-editor.org/rfc/rfc9591.html#section-4.3
fn encode_group_commitment_list(commitment_list: &[Commitment]) -> Vec<u8> {
    let mut encoded = vec![];

    for (identifier, hiding_nonce_commitment, binding_nonce_commitment) in commitment_list {
        let mut identifier_bytes = Vec::new();
        let mut hiding_nonce_commitment_bytes = Vec::new();
        let mut binding_nonce_commitment_bytes = Vec::new();

        identifier
            .0
            .serialize_compressed(&mut identifier_bytes)
            .unwrap();

        hiding_nonce_commitment
            .serialize_compressed(&mut hiding_nonce_commitment_bytes)
            .unwrap();
        binding_nonce_commitment
            .serialize_compressed(&mut binding_nonce_commitment_bytes)
            .unwrap();

        let mut encoded_commitment = [
            identifier_bytes,
            hiding_nonce_commitment_bytes,
            binding_nonce_commitment_bytes,
        ]
        .concat();

        encoded.append(&mut encoded_commitment);
    }

    encoded
}

/// Extracts and returns a `BindingFactor` from a `Vec<BindingFactor>` given a `NonZeroScalar`
/// identifier.
pub fn binding_factor_for_participant(
    binding_factor_list: &[BindingFactor],
    identifier: NonZeroScalar,
) -> ScalarField {
    binding_factor_list
        .iter()
        .find(|(id, _)| *id == identifier)
        .unwrap()
        .1
}

/// Computes and returns `Vec<BindingFactor>` based on participant `commitment_list`, `msg` and
/// the group public key `group_pk`.
///
/// Reference: https://www.rfc-editor.org/rfc/rfc9591.html#section-4.4
pub fn compute_binding_factors(
    group_pk: Element,
    commitment_list: &[Commitment],
    msg: Vec<u8>,
) -> Vec<BindingFactor> {
    let mut group_pk_encoded = vec![];
    group_pk
        .serialize_compressed(&mut group_pk_encoded)
        .unwrap();

    let msg_hash = H4(msg);
    let encoded_commitment_hash = H5(encode_group_commitment_list(commitment_list));

    let rho_input_prefix: Vec<u8> = [group_pk_encoded, msg_hash, encoded_commitment_hash].concat();

    let mut binding_factor_list = Vec::with_capacity(commitment_list.len());

    for (identifier, _, _) in commitment_list {
        let mut identifier_bytes = Vec::new();
        identifier
            .0
            .serialize_compressed(&mut identifier_bytes)
            .unwrap();

        let rho_input = [rho_input_prefix.clone(), identifier_bytes].concat();
        let binding_factor = ScalarField::from_le_bytes_mod_order(&H1(rho_input));

        binding_factor_list.push((*identifier, binding_factor));
    }

    binding_factor_list
}

pub fn compute_group_commitment(
    commitment_list: &[Commitment],
    binding_factor_list: Vec<BindingFactor>,
) -> Element {
    // TODO: fix
    let mut group_commitment = Element::ZERO;

    for (identifier, hiding_nonce_commitment, binding_nonce_commitment) in commitment_list {
        let binding_factor = binding_factor_for_participant(&binding_factor_list, *identifier);
        let binding_nonce = *binding_nonce_commitment * binding_factor;

        group_commitment += hiding_nonce_commitment + binding_nonce;
    }

    group_commitment
}

pub fn compute_challenge(
    group_commitment: Element,
    group_pk: Element,
    msg: Vec<u8>,
) -> ScalarField {
    let mut group_commitment_encoded_bytes = Vec::new();
    let mut group_pk_encoded_bytes = Vec::new();

    group_commitment
        .serialize_compressed(&mut group_commitment_encoded_bytes)
        .unwrap();
    group_pk
        .serialize_compressed(&mut group_pk_encoded_bytes)
        .unwrap();
    let challenge_input = [group_commitment_encoded_bytes, group_pk_encoded_bytes, msg].concat();
    let challenge_bytes = H2(challenge_input);

    ScalarField::from_le_bytes_mod_order(&challenge_bytes)
}

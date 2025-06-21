#![allow(non_snake_case)]

use ark_ed25519::{EdwardsProjective as Element, Fr as ScalarField};
use ark_ff::{AdditiveGroup, UniformRand};
use ark_std::rand::SeedableRng;

use crate::{
    helper::{
        BindingFactor, NonZeroScalar, binding_factor_for_participant, derive_interpolating_value,
    },
    schnorr::SchnorrSignature,
    shamir::shamir_split,
};

#[derive(Debug, Copy, Clone)]
pub struct NonceCommitment {
    pub D: Element, // commitment for hiding nonce
    pub E: Element, // commitment for binding nonce
}

/// Each signer has a secret share and can generate a signature share
/// Each signer will generate a hiding nonce and a binding nonce
#[derive(Debug, Copy, Clone)]
pub struct FrostSigner {
    identifier: ScalarField, // unique identifier for the signer

    x: ScalarField, // secret share

    d: ScalarField, // hiding nonce
    e: ScalarField, // binding nonce

    commitment: NonceCommitment,

    rho: ScalarField, // binding factor
}

impl FrostSigner {
    pub fn new(index: usize, x: ScalarField, g: Element, is_blind: bool) -> Self {
        let mut seed = [0u8; 32];
        let index_bytes = index.to_le_bytes();
        seed[..index_bytes.len()].copy_from_slice(&index_bytes);
        let mut rng = ark_std::rand::rngs::StdRng::from_seed(seed);
        let identifier = ScalarField::from(index as u64);

        // generate a hiding nonce d and its commitment D
        let d = ScalarField::rand(&mut rng);
        let D = g * d;

        // generate a binding nonce e and its commitment E
        let mut e = ScalarField::ZERO;
        if !is_blind {
            e = ScalarField::rand(&mut rng);
        }
        let E = g * e;

        Self {
            identifier,
            x,
            d,
            e,
            commitment: NonceCommitment { D, E },
            rho: ScalarField::ZERO,
        }
    }

    pub fn store_rho(&mut self, binding_factor: ScalarField) {
        self.rho = binding_factor;
    }

    pub fn sign(&self, challenge: ScalarField, x_coordinates: &[NonZeroScalar]) -> ScalarField {
        let lambda = derive_interpolating_value(
            x_coordinates,
            NonZeroScalar::new(ScalarField::from(self.identifier)),
        );
        self.d + (self.rho * self.e) + (lambda * self.x * challenge)
    }

    pub fn get_identifier(&self) -> ScalarField {
        self.identifier
    }

    pub fn get_nonce_commitment(&self) -> &NonceCommitment {
        &self.commitment
    }
}

#[derive(Debug, Clone)]
pub struct Frost {
    pub generator: Element, // generator of the group
    pub signers: Vec<FrostSigner>,
    pub group_pk: Element, // public key of the group
}

pub struct NoncePair {
    pub hiding: ScalarField,
    pub binding: ScalarField,
}

struct CommitmentPair {
    hiding: Element,
    binding: Element,
}

impl Frost {
    pub fn signature_share(threshold: usize, total_signers: usize) -> Self {
        let mut rng = ark_std::test_rng();
        let secret_key = ScalarField::rand(&mut rng);
        let generator = Element::rand(&mut rng);
        let group_pk = generator * secret_key;

        let shamir_shares = shamir_split(secret_key, threshold, total_signers);
        let signers = shamir_shares
            .iter()
            .map(|shamir_share| {
                let mut is_blind = false;
                if shamir_share.index > threshold {
                    is_blind = true; // set a few signers to be blind
                }
                FrostSigner::new(shamir_share.index, shamir_share.secret, generator, is_blind)
            })
            .collect();

        Frost {
            generator,
            signers,
            group_pk,
        }
    }

    pub fn update_binding_factors(&mut self, binding_factors: Vec<BindingFactor>) {
        for signer in self.signers.iter_mut() {
            let binding_factor = binding_factor_for_participant(
                &binding_factors,
                NonZeroScalar::new(signer.get_identifier()),
            );
            signer.store_rho(binding_factor);
        }
    }

    /// Coordinator aggregates each share to produce a final `SchnorrSignature`.
    pub fn signature_aggregate(&self, sig_shares: Vec<ScalarField>) -> ScalarField {
        let mut z = ScalarField::ZERO;

        for z_i in sig_shares {
            z += z_i;
        }

        z
    }

    pub fn verify(&self, signature: SchnorrSignature, challenge: ScalarField) -> bool {
        let lhs = self.generator * signature.s; // g^z
        let rhs = signature.R + self.group_pk * challenge;

        lhs == rhs
    }
}

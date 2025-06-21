use ark_ed25519::{EdwardsProjective as Element, Fr as ScalarField};
use ark_ff::{AdditiveGroup, UniformRand};

use crate::{
    helper::{compute_binding_factors, compute_group_commitment, derive_interpolating_value, BindingFactor, Commitment, NonZeroScalar},
    schnorr::SchnorrSignature,
};

struct NonceCommitment {
    D: Element, // commitment for hiding nonce
    E: Element, // commitment for binding nonce
}

/// Each signer has a secret share and can generate a signature share
/// Each signer will generate a hiding nonce and a binding nonce
struct FrostSigner {
    identifier: usize, // unique identifier for the signer

    x: ScalarField, // secret share
    g: Element, // generator of the group

    d: ScalarField, // hiding nonce
    e: ScalarField, // binding nonce

    commitment: NonceCommitment,

    rho: ScalarField, // binding factor
}

impl FrostSigner {
    pub fn new(&self, identifier: usize, x: ScalarField, g: Element) -> Self {
        let mut rng = ark_std::test_rng();
        
        // generate a hiding nonce d and its commitment D
        let d = ScalarField::rand(&mut rng);
        let D = self.g * d;

        // generate a binding nonce e and its commitment E
        let e = ScalarField::rand(&mut rng);
        let E = self.g * e;

        Self { identifier, x, g, d, e, commitment: NonceCommitment { D, E }, rho: ScalarField::ZERO }
    }

    pub fn store_rho(&mut self, binding_factors: Vec<BindingFactor>) {
        let (_, rho) = binding_factors[self.identifier];
        self.rho = rho;
    }

    pub fn sign(&self, challenge: ScalarField, x_coordinates: &[NonZeroScalar]) -> ScalarField {
        let lambda = derive_interpolating_value(x_coordinates, NonZeroScalar::new(ScalarField::from(self.x)));
        self.d + (self.rho * self.e) + (lambda * self.x * challenge)
    } 
}

struct Frost {}

impl Frost {
    pub fn commit() {}

    pub fn signature_share() {}

    /// Coordinator aggregates each share to produce a final `SchnorrSignature`.
    pub fn signature_aggregate(
        commitment_list: Vec<Commitment>,
        msg: Vec<u8>,
        group_pk: Element,
        sig_shares: Vec<ScalarField>,
    ) -> SchnorrSignature {
        let binding_factor_list = compute_binding_factors(group_pk, &commitment_list, msg);
        let group_commitment = compute_group_commitment(&commitment_list, binding_factor_list);

        let mut z = ScalarField::ZERO;

        for z_i in sig_shares {
            z += z_i;
        }

        return SchnorrSignature {
            R: group_commitment,
            s: z,
        };
    }

    pub fn verify() {}
}

pub fn sign_signature_share(secret_share: ScalarField, challenge: ScalarField) {}


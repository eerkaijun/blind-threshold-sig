use ark_ed25519::{EdwardsProjective as Element, Fr as ScalarField};
use ark_ff::AdditiveGroup;

use crate::{
    helper::{Commitment, compute_binding_factors, compute_group_commitment},
    schnorr::SchnorrSignature,
};

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


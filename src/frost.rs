use ark_ec::PrimeGroup;
use ark_ed25519::{EdwardsProjective as Element, Fr as ScalarField};
use ark_ff::{AdditiveGroup, UniformRand};

use crate::{
    helper::{
        BindingFactor, Commitment, NonZeroScalar, compute_binding_factors,
        compute_group_commitment, derive_interpolating_value, nonce_generate,
    },
    schnorr::SchnorrSignature,
    shamir::shamir_split,
};

pub struct NonceCommitment {
    pub D: Element, // commitment for hiding nonce
    pub E: Element, // commitment for binding nonce
}

/// Each signer has a secret share and can generate a signature share
/// Each signer will generate a hiding nonce and a binding nonce
pub struct FrostSigner {
    identifier: ScalarField, // unique identifier for the signer
    index: usize,            // index in the list of signers

    x: ScalarField, // secret share
    g: Element,     // generator of the group

    d: ScalarField, // hiding nonce
    e: ScalarField, // binding nonce

    commitment: NonceCommitment,

    rho: ScalarField, // binding factor
}

impl FrostSigner {
    pub fn new(index: usize, x: ScalarField, g: Element) -> Self {
        let mut rng = ark_std::test_rng();
        let identifier = ScalarField::from(index as u64);

        // generate a hiding nonce d and its commitment D
        let d = ScalarField::rand(&mut rng);
        let D = g * d;

        // generate a binding nonce e and its commitment E
        let e = ScalarField::rand(&mut rng);
        let E = g * e;

        Self {
            identifier,
            index,
            x,
            g,
            d,
            e,
            commitment: NonceCommitment { D, E },
            rho: ScalarField::ZERO,
        }
    }

    pub fn store_rho(&mut self, binding_factors: Vec<BindingFactor>) {
        let (_, rho) = binding_factors[self.index];
        self.rho = rho;
    }

    pub fn sign(&self, challenge: ScalarField, x_coordinates: &[NonZeroScalar]) -> ScalarField {
        let lambda = derive_interpolating_value(
            x_coordinates,
            NonZeroScalar::new(ScalarField::from(self.x)),
        );
        self.d + (self.rho * self.e) + (lambda * self.x * challenge)
    }

    pub fn get_nonce_commitment(&self) -> &NonceCommitment {
        &self.commitment
    }
}

pub struct Frost {
    pub signers: Vec<FrostSigner>,
    pub group_pk: Element, // public key of the group
}

struct NoncePair {
    hiding: ScalarField,
    binding: ScalarField,
}

struct CommitmentPair {
    hiding: Element,
    binding: Element,
}

impl Frost {
    /// Generates and returns a participant's hiding and binding nonces and their commitments in
    /// a `NoncePair` and a `CommitmentPair` tuple.
    pub fn commit(sk_i: ScalarField) -> (NoncePair, CommitmentPair) {
        let hiding_nonce = nonce_generate(sk_i);
        let binding_nonce = nonce_generate(sk_i);

        let hiding_nonce_commitment = Element::generator() * hiding_nonce;
        let binding_nonce_commitment = Element::generator() * binding_nonce;

        return (
            NoncePair {
                hiding: hiding_nonce,
                binding: binding_nonce,
            },
            CommitmentPair {
                hiding: hiding_nonce_commitment,
                binding: binding_nonce_commitment,
            },
        );
    }

    pub fn signature_share(threshold: usize, total_signers: usize) -> Self {
        let mut rng = ark_std::test_rng();
        let secret_key = ScalarField::rand(&mut rng);
        let generator = Element::rand(&mut rng);
        let group_pk = generator * secret_key;

        let shamir_shares = shamir_split(secret_key, threshold, total_signers);
        let signers = shamir_shares
            .iter()
            .map(|shamir_share| {
                FrostSigner::new(shamir_share.index, shamir_share.secret, generator)
            })
            .collect();

        Frost { signers, group_pk }
    }

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

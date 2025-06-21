use crate::{frost::NoncePair, helper::nonce_generate};
use ark_ed25519::Fr as ScalarField;
use ark_ff::{AdditiveGroup, Field};

pub struct CollaborativeSigner {
    /// The public nonce that the `CollaborativeSigner` should send to the
    /// coordinator.
    curr_nonce: ScalarField,
}

impl CollaborativeSigner {
    pub fn new() -> Self {
        return Self {
            //TODO: this is not very cryptographically rigorous xD
            curr_nonce: ScalarField::ONE,
        };
    }

    /// Returns (D, 0).
    pub fn nonce_pair(mut self: Self) -> NoncePair {
        let nonce = self.curr_nonce;
        self.curr_nonce += ScalarField::ONE;
        return NoncePair {
            hiding: nonce,
            binding: ScalarField::ZERO,
        };
    }
}

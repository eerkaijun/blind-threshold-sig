use ark_ed25519::Fr as ScalarField;

use crate::{
    frost::{Frost, FrostSigner},
    helper::{Commitment, NonZeroScalar, compute_binding_factors},
};

pub mod ciphersuite;
pub mod frost;
pub mod helper;
pub mod schnorr;
pub mod shamir;

fn main() {
    println!("Hello, Schnorr!");

    let message = b"asia is underrated";

    // Step1: At the start of the protocol, a secret key is generated and shared among signers
    // In this example, we use a threshold signature scheme of 5 signers with a threshold of 3
    let frost_protocol = Frost::signature_share(3, 5);

    // Step2: Each of these signers generate a hiding nonce and a binding nonce respectively
    // and send the commitment of these nonces to the coordinator
    // The coordinator collects these commitments and compute the binding factors rho for all signers
    let mut commitments: Vec<Commitment> = Vec::new();
    for (index, signer) in frost_protocol.signers.iter().enumerate() {
        let commitment = signer.get_nonce_commitment();
        commitments.push((
            NonZeroScalar::new(ScalarField::from((index + 1) as u64)),
            commitment.D,
            commitment.E,
        ));
    }
    let binding_factors =
        compute_binding_factors(frost_protocol.group_pk, &commitments, message.to_vec());
}

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
    let mut frost_protocol = Frost::signature_share(3, 5);

    // Step2: Each of these signers generate a hiding nonce and a binding nonce respectively
    // and send the commitment of these nonces to the coordinator
    // The coordinator collects these commitments and compute the binding factors rho for all signers
    let mut commitments: Vec<Commitment> = Vec::new();
    for signer in frost_protocol.clone().signers {
        // FIXME: clean up various commitment types
        let commitment = signer.get_nonce_commitment();
        commitments.push((
            NonZeroScalar::new(signer.get_identifier()),
            commitment.D,
            commitment.E,
        ));
    }
    let binding_factors =
        compute_binding_factors(frost_protocol.group_pk, &commitments, message.to_vec());

    // Step3: Each signer obtains its own binding factor rho
    frost_protocol.update_binding_factors(binding_factors);
}

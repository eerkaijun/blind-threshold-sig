//! The main function contains a naive end-to-end flow of the FROST protocol, with the tweaks
//! suggested in this [gist](https://gist.github.com/nickfarrow/4be776782bce0c12cca523cbc203fb9d/) to allow for blind signatures from a collaborative custodian. This
//! enables the user of the custodian to protect their own privacy as well as possibly have the
//! option of switching away from this custodian at their own discretion.
//!
//! For simplicity, we make no distinction of a 'collaborative custodian' in our implementation;
//! we simply assign certain signers during setup as 'blind signers'.
//!
//! The rough flow goes like this, in steps:
//!
//! 1. At the start of the protocol, a secret key is generated and shared among signers.
//!    This can either be done through a trusted dealer or a distributed key generation mechanism.
//!    In this step, we also set a few signers above the `threshold` to be 'blind signers' as
//!    suggested in the
//!    [draft](https://gist.github.com/nickfarrow/4be776782bce0c12cca523cbc203fb9d?permalink_comment_id=4676206#gistcomment-4676206) instead of doing a key re-distribution and enrolment process for
//!    simplicity.
//!
//! 2. In the [RFC](https://www.rfc-editor.org/rfc/rfc9591.html), a 'Coordinator' is chosen in the protocol, responsible for various group
//!    actions such as aggregating signatures. In our simple example, the Coordinator is just
//!    one of the signers.
//!
//! 3. Each signer generates a hiding and a binding nonce respectively and sends their commitments
//!    to the Coordinator. The Coordinator collects these commitments and computes the
//!    binding factors for all signers.
//!
//! 4.  Each signer generates a signature share using its secret key share, nonces and binding
//!     factor.
//!
//! 5. The Coordinator aggregates these signature shares to produce a signature.
//!
//! 6. The Coordinator verifies the signature.

use crate::{
    frost::Frost,
    helper::{
        Commitment, NonZeroScalar, compute_binding_factors, compute_challenge,
        compute_group_commitment,
    },
    schnorr::SchnorrSignature,
};
use ark_ed25519::Fr as ScalarField;

pub mod ciphersuite;
pub mod frost;
pub mod helper;
pub mod schnorr;
pub mod shamir;

fn main() {
    println!("Hello, Blind Schnorr!");

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
    frost_protocol.update_binding_factors(binding_factors.clone());

    // Step4: Each signer generates a signature share using its secret share, nonces and binding factor
    let x_coordinates: Vec<NonZeroScalar> = frost_protocol
        .signers
        .iter()
        .map(|signer| NonZeroScalar::new(signer.get_identifier()))
        .collect();
    let group_commitment = compute_group_commitment(&commitments, binding_factors);
    let challenge = compute_challenge(group_commitment, frost_protocol.group_pk, message.to_vec());
    let mut signature_shares = Vec::new();
    for signer in frost_protocol.clone().signers {
        let sig_share = signer.sign(ScalarField::from(challenge), &x_coordinates);
        signature_shares.push(sig_share);
    }

    // Step5: The coordinator aggregates the signature shares to produce a signature
    // TODO: we only need to aggregate threshold number of shares, not all
    let signature = frost_protocol.signature_aggregate(signature_shares);
    let schnorr_signature = SchnorrSignature {
        R: group_commitment,
        s: signature,
    };

    // Step6: The coordinator verifies the signature
    let verification_result = frost_protocol.verify(schnorr_signature, challenge);
    println!("Signature verification result: {}", verification_result);
}

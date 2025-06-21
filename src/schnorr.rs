use ark_ed25519::{EdwardsProjective as G, Fr as ScalarField};
use ark_ff::{AdditiveGroup, Field, UniformRand};

/// A Schnorr signature contains a point R which is commitment of nonce k
/// R = g^k where g is the generator of the group,
/// and a scalar s which is the signature value
/// s = k + H(R || P || m) * x
/// where H is a hash function, P is the public key, m is the message, and x is the private key.
struct SchnorrSignature {
    pub R: G,
    pub s: ScalarField,
}

struct Signer {
    pub x: ScalarField, // private key
    pub P: G, // public key
    pub g: G, // generator of the group (P = g^x)
}

impl Signer {
    pub fn new(x: ScalarField) -> Self {
        // TODO: i think it's better to use thread_rng and store in Signer struct
        let mut rng = ark_std::test_rng();
        let g = G::rand(&mut rng);

        // generate public key P = g^x
        let P = g * x;
        Signer { x, P, g }
    }

    pub fn sign(&self, message: &[u8]) -> SchnorrSignature {
        // generate a random nonce k
        let mut rng = ark_std::test_rng();
        let k = ScalarField::rand(&mut rng);

        // compute commitment R = g^k
        let R = self.g * k;

        // compute the hash H(R || P || m)
        // TODO: just a placeholder right now, replace with actual hash function
        let hash_output = ScalarField::ONE;

        // compute the signature value s = k + H(R || P || m) * x
        let s = k + (hash_output * self.x);

        SchnorrSignature { R, s }
    }
}

struct Verifier {}

impl Verifier {
    pub fn verify(signature: &SchnorrSignature, message: &[u8], P: G, g: G) -> bool {
        // compute the hash H(R || P || m)
        let hash_output = ScalarField::ONE;

        // lhs is g^s
        let lhs = g * signature.s;

        // rhs is R * (g^e) where e = H(R || P || m)
        // TODO: just a placeholder right now, replace with actual hash function
        let rhs = signature.R + (P * hash_output);

        // check if g^s == R * (g^e)
        lhs == rhs
    }
}

#[test]
fn test_signature_verification() {
    let message = b"testing";

    let signer = Signer::new(ScalarField::from(42u64));
    let signature = signer.sign(message);
    let is_valid = Verifier::verify(&signature, message, signer.P, signer.g);

    assert!(is_valid, "Signature verification failed");
}
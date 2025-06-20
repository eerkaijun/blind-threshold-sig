use ark_bls12_381::{G1Projective as G, Fr as ScalarField};
use ark_ff::UniformRand;

/// A Schnorr signature contains a point R which is commitment of nonce k
/// R = g^k where g is the generator of the group,
/// and a scalar s which is the signature value
/// s = k + H(R || P || m) * x
/// where H is a hash function, P is the public key, m is the message, and x is the private key.
struct Signature {
    pub R: G,
    pub s: ScalarField,
}

struct Signer {
    pub x: ScalarField, // private key
    pub P: G, // public key
}

impl Signer {
    pub fn new(x: ScalarField) -> Self {
        let mut rng = ark_std::test_rng();
        let g = G::rand(&mut rng);

        // generate public key P = g^x
        let P = g * x;
        Signer { x, P }
    }

    pub fn sign(&self) {

    }
}
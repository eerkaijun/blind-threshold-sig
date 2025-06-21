//! This module contains a simple Shamir Secret Sharing implementation used during FROST setup.
use ark_ed25519::Fr as ScalarField;
use ark_ff::{AdditiveGroup, Field, UniformRand};

pub struct ShamirShare {
    pub index: usize,        // index of the share
    pub secret: ScalarField, // secret share
}

pub fn shamir_split(secret: ScalarField, t: usize, n: usize) -> Vec<ShamirShare> {
    assert!(t <= n, "threshold cannot exceed number of shares");
    assert!(t >= 2, "threshold must be at least 2");

    let mut rng = ark_std::test_rng();

    // generate random coefficients a_1 .. a_{t-1}
    let mut coeffs = vec![secret];
    for _ in 1..t {
        coeffs.push(ScalarField::rand(&mut rng));
    }

    // evaluate polynomial at x = 1..n to get shares
    (1..=n)
        .map(|i| {
            let x = ScalarField::from(i as u64);
            let mut y = ScalarField::ZERO;
            for (j, coeff) in coeffs.iter().enumerate() {
                y += *coeff * x.pow([j as u64]);
            }
            ShamirShare {
                index: i,
                secret: y,
            }
        })
        .collect()
}

pub fn shamir_reconstruct(shares: &[ShamirShare]) -> ScalarField {
    let mut secret = ScalarField::ZERO;

    for (
        i,
        ShamirShare {
            index: x_i,
            secret: y_i,
        },
    ) in shares.iter().enumerate()
    {
        let mut numerator = ScalarField::ONE;
        let mut denominator = ScalarField::ONE;

        for (
            j,
            ShamirShare {
                index: x_j,
                secret: _,
            },
        ) in shares.iter().enumerate()
        {
            if i != j {
                numerator *= ScalarField::ZERO - ScalarField::from(*x_j as u64); // x_j is negated since x = 0
                denominator *= ScalarField::from(*x_i as u64) - ScalarField::from(*x_j as u64);
            }
        }

        let lagrange_coeff = numerator * denominator.inverse().unwrap(); // Lagrange basis L_i(0)
        secret += y_i * &lagrange_coeff;
    }

    secret
}

#[test]
fn test_shamir_split_reconstruct() {
    let secret = ScalarField::from(42u64);
    let t = 3; // threshold
    let n = 5; // total shares
    let shares = shamir_split(secret, t, n);
    assert_eq!(shares.len(), n);

    // Reconstruct the secret using the first t shares
    let reconstructed_secret = shamir_reconstruct(&shares[..3]);
    assert_eq!(reconstructed_secret, secret);
}

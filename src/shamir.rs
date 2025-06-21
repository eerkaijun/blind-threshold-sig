use ark_bls12_381::Fr as ScalarField;
use ark_ff::{AdditiveGroup, Field, UniformRand};

pub fn shamir_split(secret: ScalarField, t: usize, n: usize) -> Vec<(ScalarField, ScalarField)> {
    assert!(t <= n, "threshold cannot exceed number of shares");
    assert!(t >= 2, "threshold must be at least 2");

    let mut rng = ark_std::test_rng();

    // generate random coefficients a_1 .. a_{t-1}
    let mut coeffs = vec![secret];
    for _ in 1..t {
        coeffs.push(ScalarField::rand(&mut rng));
    }

    // evaluate polynomial at x = 1..n to get shares
    (1..=n).map(|i| {
        let x = ScalarField::from(i as u64);
        let mut y = ScalarField::ZERO;
        for (j, coeff) in coeffs.iter().enumerate() {
            y += *coeff * x.pow([j as u64]);
        }
        (x, y)
    }).collect()
}

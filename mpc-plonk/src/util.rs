///! Extra algebra utils
use ark_ff::{FftField, FromBytes, ToBytes, PubUniformRand};
use ark_poly::univariate::DensePolynomial;
use ark_poly::UVPolynomial;
use ark_std::marker::PhantomData;
use ark_std::rand::{RngCore, SeedableRng};
use digest::{generic_array::GenericArray, Digest};
use rand_chacha::ChaChaRng;

/// Computes f(a*X) from a and f(X)
pub fn shift<F: FftField>(mut f: DensePolynomial<F>, a: F) -> DensePolynomial<F> {
    let mut s = F::one();
    for c in &mut f.coeffs {
        *c *= s;
        s *= a;
    }
    f
}

pub fn interpolate<F: FftField>(points: &[(F, F)]) -> DensePolynomial<F> {
    let k = points.len();
    let mut scaled_lagrange_basis: Vec<DensePolynomial<F>> = (0..k)
        .map(|j| {
            let mut basis = (0..k).filter(|i| *i != j).fold(
                DensePolynomial::from_coefficients_vec(vec![F::one()]),
                |acc, m| {
                    let xm = points[m].0;
                    let xj = points[j].0;
                    let d = (xj - xm).inverse().unwrap();
                    acc.naive_mul(&DensePolynomial::from_coefficients_vec(vec![-xm * d, d]))
                },
            );
            let yj = points[j].1;
            for c in &mut basis.coeffs {
                *c *= yj;
            }
            basis
        })
        .collect();
    let p = scaled_lagrange_basis.pop().unwrap();
    scaled_lagrange_basis.into_iter().fold(p, |a, b| a + b)
}

/// A `SeedableRng` that refreshes its seed by hashing together the previous seed
/// and the new seed material.
// TODO: later: re-evaluate decision about ChaChaRng
pub struct FiatShamirRng<D: Digest> {
    r: ChaChaRng,
    seed: GenericArray<u8, D::OutputSize>,
    #[doc(hidden)]
    digest: PhantomData<D>,
}

impl<D: Digest> RngCore for FiatShamirRng<D> {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        self.r.next_u32()
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.r.next_u64()
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.r.fill_bytes(dest);
    }

    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), ark_std::rand::Error> {
        Ok(self.r.fill_bytes(dest))
    }
}

impl<D: Digest> FiatShamirRng<D> {
    /// Create a new `Self` by initializing with a fresh seed.
    /// `self.seed = H(self.seed || new_seed)`.
    #[inline]
    pub fn from_seed<'a, T: 'a + ToBytes>(seed: &'a T) -> Self {
        let mut bytes = Vec::new();
        seed.write(&mut bytes).expect("failed to convert to bytes");
        let seed = D::digest(&bytes);
        let r_seed: [u8; 32] = FromBytes::read(seed.as_ref()).expect("failed to get [u32; 8]");
        let r = ChaChaRng::from_seed(r_seed);
        Self {
            r,
            seed,
            digest: PhantomData,
        }
    }

    /// Refresh `self.seed` with new material. Achieved by setting
    /// `self.seed = H(self.seed || new_seed)`.
    #[inline]
    pub fn absorb<'a, T: 'a + ToBytes>(&mut self, seed: &'a T) {
        let mut bytes = Vec::new();
        seed.write(&mut bytes).expect("failed to convert to bytes");
        bytes.extend_from_slice(&self.seed);
        self.seed = D::digest(&bytes);
        let seed: [u8; 32] = FromBytes::read(self.seed.as_ref()).expect("failed to get [u32; 8]");
        self.r = ChaChaRng::from_seed(seed);
    }

    pub fn gen<T: PubUniformRand>(&mut self) -> T {
        T::pub_rand(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_poly::Polynomial;

    type F = ark_bls12_377::Fr;
    fn interp_test(pts: &[(F, F)]) {
        let p = interpolate(&pts);
        for (x, y) in pts {
            println!("{} vs {} at\n{}", p.evaluate(x), *y, x);
            assert_eq!(p.evaluate(x), *y);
        }
        assert!(p.degree() <= pts.len());
    }

    #[test]
    fn interp_test_1() {
        interp_test(&[(F::from(0u64), F::from(1u64))]);
    }

    #[test]
    fn interp_test_2() {
        interp_test(&[
            (F::from(0u64), F::from(1u64)),
            (F::from(1u64), F::from(3u64)),
        ]);
    }

    #[test]
    fn interp_test_5() {
        let rng = &mut ark_std::test_rng();
        for _i in 0..10 {
            interp_test(&[
                (F::from(0u64), F::rand(rng)),
                (F::from(1u64), F::rand(rng)),
                (F::from(3u64), F::rand(rng)),
                (F::from(8u64), F::rand(rng)),
                (F::from(9u64), F::rand(rng)),
            ]);
        }
    }
}

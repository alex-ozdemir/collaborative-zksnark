use ark_poly::{univariate, Polynomial, UVPolynomial};

use super::*;

pub mod pc;

type F = ark_bls12_377::Fr;
type P = univariate::DensePolynomial<MpcVal<F>>;
type MP = MpcVal<P>;

impl<'a> std::ops::AddAssign<(MpcVal<F>, &'a MP)> for MP {
    fn add_assign(&mut self, (scalar, f): (MpcVal<F>, &'a MP)) {
        self.val += (scalar, &f.val);
    }
}

impl Polynomial<MpcVal<F>> for MP {
    type Point = MpcVal<F>;
    fn degree(&self) -> usize {
        self.val.degree()
    }
    fn evaluate(&self, p: &Self::Point) -> MpcVal<F> {
        self.val.evaluate(p)
    }
}

impl UVPolynomial<MpcVal<F>> for MP {
    fn from_coefficients_slice(s: &[MpcVal<F>]) -> Self {
        assert!(s.len() > 0);
        let first_shared = s[0].shared;
        assert!(s.iter().all(|x| x.shared == first_shared));
        MpcVal::new(
            <P>::from_coefficients_slice(s),
            first_shared,
        )
    }
    fn from_coefficients_vec(s: Vec<MpcVal<F>>) -> Self {
        assert!(s.len() > 0);
        let first_shared = s[0].shared;
        assert!(s.iter().all(|x| x.shared == first_shared));
        MpcVal::new(
            <P>::from_coefficients_vec(s),
            first_shared,
        )
    }
    fn coeffs(&self) -> &[MpcVal<F>] {
        self.val.coeffs()
    }
    fn rand<R>(d: usize, r: &mut R) -> Self
    where
        R: rand::Rng,
    {
        MpcVal::from_shared(<P>::rand(d, r))
    }
}
impl<'a, 'b> std::ops::Div<&'b MpcVal<P>> for &'a MpcVal<P> {
    type Output = MpcVal<P>;
    fn div(self, other: &MpcVal<P>) -> MpcVal<P> {
        assert!(!other.shared);
        if self.shared {
            panic!("Shared div");
            let mut cs = self.val.coeffs().to_owned();
            for c in &mut cs {
                c.set_shared(false);
            }
            let self_ = MP::from_coefficients_vec(cs);
            let r = &self_ / other;
            let mut cs = r.val.coeffs().to_owned();
            for c in &mut cs {
                c.set_shared(true);
            }
            MP::from_coefficients_vec(cs)
        } else {
            MpcVal::new(&self.val / &other.val, false)
        }
    }
}

// impl_uv_poly!(
//     ark_bls12_377::Fr,
//     MpcVal<univariate::DensePolynomial<MpcVal<ark_bls12_377::Fr>>>
// );

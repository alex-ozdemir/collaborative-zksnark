//! Implementation based on ["Malicious Security Comes Free in Honest-Majority
//! MPC"](https://ia.cr/2020/134) by Goyal and Song.

#[allow(unused_macros)]
macro_rules! print_list {
    ($list:expr) => {
        println!("{}:", std::stringify!($list));
        for (i, j) in (&$list).into_iter().enumerate() {
            println!("  {}: {}", i, j);
        }
    };
}
#[allow(unused_macros)]
macro_rules! dd {
    ($list:expr) => {
        println!("{}: {}", std::stringify!($list), $list);
    };
}

use crate::channel::MpcSerNet;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{
    bytes::{FromBytes, ToBytes},
    prelude::*,
    FftField,
};
use ark_poly::{
    domain::{EvaluationDomain, MixedRadixEvaluationDomain},
    Polynomial, UVPolynomial,
};
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, Flags, SerializationError,
};
use ark_std::{end_timer, start_timer};
use mpc_net::{MpcMultiNet as Net, MpcNet};

use once_cell::sync::OnceCell;
use std::any::{Any, TypeId};
use std::borrow::Cow;
use std::cmp::Ord;
use std::collections::HashMap;
use std::fmt::{self, Debug, Display, Formatter};
use std::hash::Hash;
use std::io::{self, Read, Write};
use std::marker::PhantomData;
use std::sync::Mutex;

use derivative::Derivative;
use lazy_static::lazy_static;
use log::debug;
use rand::Rng;

use super::field::{
    DenseOrSparsePolynomial, DensePolynomial, ExtFieldShare, FieldShare, SparsePolynomial,
};
use super::BeaverSource;
use crate::msm::Msm;
use crate::share::pairing::{AffProjShare, PairingShare};
use crate::Reveal;

lazy_static! {
    static ref TYPE_LISTS: Mutex<HashMap<TypeId, Vec<Box<dyn Any + Send>>>> =
        Mutex::new(HashMap::new());
    static ref SHARE_DOMAIN: OnceCell<Box<dyn Any + Send + Sync>> = OnceCell::new();
}

fn take_types<T: Any + Send>() -> Vec<T> {
    let mut lists = TYPE_LISTS.lock().unwrap();
    let type_id = TypeId::of::<T>();
    let list = lists.remove(&type_id).unwrap_or_else(|| Vec::new());
    list.into_iter()
        .map(|x| *x.downcast::<T>().unwrap())
        .collect()
}
fn add_type<T: Any + Send>(t: T) {
    let mut lists = TYPE_LISTS.lock().unwrap();
    let type_id = TypeId::of::<T>();
    use std::collections::hash_map::Entry;
    match lists.entry(type_id) {
        Entry::Occupied(o) => o.into_mut().push(Box::new(t)),
        Entry::Vacant(v) => {
            v.insert(vec![Box::new(t)]);
        }
    };
}
fn add_types<T: Any + Send>(ts: Vec<T>) {
    for t in ts {
        add_type(t);
    }
}

/// Malicious degree
pub fn t() -> usize {
    (Net::n_parties() - 1) / 2
}

pub fn domain<F: FftField>() -> &'static MixedRadixEvaluationDomain<F> {
    SHARE_DOMAIN.get_or_init(|| {
        let d = MixedRadixEvaluationDomain::<F>::new(Net::n_parties()).unwrap();
        assert_eq!(d.size(), Net::n_parties(),
            "Attempted to build an evaluation domain of size {}, but could only get one of size {}.\nThis domain is needed in order to support Shamir shares for this many parties", Net::n_parties(), d.size(), );
        Box::new(d)
    }).downcast_ref().unwrap()
}

pub mod field {
    use super::*;

    /// A Goyal-Song '20 share.
    ///
    /// This is an evaluation of a polynomial at the party-number's position in the multiplicative
    /// subgroup of order equal to the number of parties.
    #[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
    pub struct GszFieldShare<F: Field> {
        pub val: F,
        pub degree: usize,
    }

    impl<T: FftField> Display for GszFieldShare<T> {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.val)
        }
    }
    impl<T: FftField> Debug for GszFieldShare<T> {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "{:?}", self.val)
        }
    }
    impl<T: FftField> ToBytes for GszFieldShare<T> {
        fn write<W: Write>(&self, _writer: W) -> io::Result<()> {
            unimplemented!("write")
        }
    }
    impl<T: FftField> FromBytes for GszFieldShare<T> {
        fn read<R: Read>(_reader: R) -> io::Result<Self> {
            unimplemented!("read")
        }
    }
    impl<T: FftField> CanonicalSerialize for GszFieldShare<T> {
        fn serialize<W: Write>(&self, _writer: W) -> Result<(), SerializationError> {
            unimplemented!("serialize")
        }
        fn serialized_size(&self) -> usize {
            unimplemented!("serialized_size")
        }
    }
    impl<T: FftField> CanonicalSerializeWithFlags for GszFieldShare<T> {
        fn serialize_with_flags<W: Write, F: Flags>(
            &self,
            _writer: W,
            _flags: F,
        ) -> Result<(), SerializationError> {
            unimplemented!("serialize_with_flags")
        }

        fn serialized_size_with_flags<F: Flags>(&self) -> usize {
            unimplemented!("serialized_size_with_flags")
        }
    }
    impl<T: FftField> CanonicalDeserialize for GszFieldShare<T> {
        fn deserialize<R: Read>(_reader: R) -> Result<Self, SerializationError> {
            unimplemented!("deserialize")
        }
    }
    impl<T: FftField> CanonicalDeserializeWithFlags for GszFieldShare<T> {
        fn deserialize_with_flags<R: Read, F: Flags>(
            _reader: R,
        ) -> Result<(Self, F), SerializationError> {
            unimplemented!("deserialize_with_flags")
        }
    }
    impl<T: FftField> UniformRand for GszFieldShare<T> {
        fn rand<R: Rng + ?Sized>(_rng: &mut R) -> Self {
            rand()
        }
    }

    impl<F: FftField> Reveal for GszFieldShare<F> {
        type Base = F;

        fn reveal(self) -> F {
            open(&self)
        }
        fn from_public(f: F) -> Self {
            Self { val: f, degree: 0 }
        }
        fn from_add_shared(_f: F) -> Self {
            unimplemented!()
        }
        fn unwrap_as_public(self) -> F {
            self.val
        }
        fn king_share<R: Rng>(f: Self::Base, _rng: &mut R) -> Self {
            let fs = vec![f; Net::n_parties()];
            let king_f = Net::recv_from_king(if Net::am_king() { Some(fs) } else { None });
            Self {
                val: king_f,
                degree: t(),
            }
        }
        fn king_share_batch<R: Rng>(f: Vec<Self::Base>, _rng: &mut R) -> Vec<Self> {
            let fs = vec![f; Net::n_parties()];
            let king_fs = Net::recv_from_king(if Net::am_king() { Some(fs) } else { None });
            king_fs
                .into_iter()
                .map(|king_f| Self {
                    val: king_f,
                    degree: t(),
                })
                .collect()
        }
    }
    impl<F: FftField> GszFieldShare<F> {
        fn poly_share<'a>(
            p: DenseOrSparsePolynomial<Self>,
        ) -> ark_poly::univariate::DenseOrSparsePolynomial<'a, F> {
            match p {
                Ok(p) => ark_poly::univariate::DenseOrSparsePolynomial::DPolynomial(Cow::Owned(
                    Self::d_poly_share(p),
                )),
                Err(p) => ark_poly::univariate::DenseOrSparsePolynomial::SPolynomial(Cow::Owned(
                    Self::s_poly_share(p),
                )),
            }
        }
        fn d_poly_share(p: DensePolynomial<Self>) -> ark_poly::univariate::DensePolynomial<F> {
            ark_poly::univariate::DensePolynomial::from_coefficients_vec(
                p.into_iter().map(|s| s.val).collect(),
            )
        }
        fn s_poly_share(p: SparsePolynomial<Self>) -> ark_poly::univariate::SparsePolynomial<F> {
            ark_poly::univariate::SparsePolynomial::from_coefficients_vec(
                p.into_iter().map(|(i, s)| (i, s.val)).collect(),
            )
        }
        fn poly_share2<'a>(
            p: DenseOrSparsePolynomial<F>,
        ) -> ark_poly::univariate::DenseOrSparsePolynomial<'a, F> {
            match p {
                Ok(p) => ark_poly::univariate::DenseOrSparsePolynomial::DPolynomial(Cow::Owned(
                    ark_poly::univariate::DensePolynomial::from_coefficients_vec(p),
                )),
                Err(p) => ark_poly::univariate::DenseOrSparsePolynomial::SPolynomial(Cow::Owned(
                    ark_poly::univariate::SparsePolynomial::from_coefficients_vec(p),
                )),
            }
        }
        fn d_poly_unshare(
            p: ark_poly::univariate::DensePolynomial<F>,
            degree: usize,
        ) -> DensePolynomial<Self> {
            p.coeffs
                .into_iter()
                .map(|val| Self { degree, val })
                .collect()
        }
    }

    impl<F: FftField> FieldShare<F> for GszFieldShare<F> {
        fn add(&mut self, other: &Self) -> &mut Self {
            self.val += other.val;
            self
        }

        fn shift(&mut self, other: &F) -> &mut Self {
            self.val += other;
            self
        }

        fn scale(&mut self, other: &F) -> &mut Self {
            self.val *= other;
            self
        }

        fn sub(&mut self, other: &Self) -> &mut Self {
            self.val -= other.val;
            self
        }

        fn neg(&mut self) -> &mut Self {
            self.val = -self.val;
            self
        }

        fn batch_open(selfs: impl IntoIterator<Item = Self>) -> Vec<F> {
            let (self_vec, mut deg_vec): (Vec<F>, Vec<usize>) =
                selfs.into_iter().map(|s| (s.val, s.degree)).unzip();
            let timer = start_timer!(|| format!("Batch open: {}", self_vec.len()));
            let mut all_vals = Net::broadcast(&self_vec);
            let mut out = Vec::new();
            while all_vals[0].len() > 0 {
                let vals: Vec<F> = all_vals.iter_mut().map(|v| v.pop().unwrap()).collect();
                out.push(open_degree_vec(vals, deg_vec.pop().unwrap()));
            }
            out.reverse();
            end_timer!(timer);
            out
        }

        /// Multiply two t-shares, consuming a double-share.
        ///
        /// Protocol 8.
        fn mul<S: BeaverSource<Self, Self, Self>>(self, other: Self, _source: &mut S) -> Self {
            mult(self, &other, true)
        }

        /// Multiply many pairs of shares, consuming many double-shares.
        fn batch_mul<S: BeaverSource<Self, Self, Self>>(
            xs: Vec<Self>,
            ys: Vec<Self>,
            _source: &mut S,
        ) -> Vec<Self> {
            batch_mult(xs, &ys, true)
        }

        fn inv<S: super::BeaverSource<Self, Self, Self>>(self, _source: &mut S) -> Self {
            let mut r = rand::<F>();
            let self_r = self.mul(r, _source);
            let self_r = open(&self_r);
            let self_r_inv = self_r.inverse().unwrap();
            r.scale(&self_r_inv);
            r
        }
        fn batch_inv<S: BeaverSource<Self, Self, Self>>(
            xs: Vec<Self>,
            source: &mut S,
        ) -> Vec<Self> {
            let rs: Vec<_> = (0..xs.len()).map(|_| rand::<F>()).collect();
            let self_rs = Self::batch_mul(xs, rs.clone(), source);
            let mut self_rs = Self::batch_open(self_rs);
            for x in &mut self_rs {
                x.inverse_in_place().unwrap();
            }
            rs.into_iter()
                .zip(&self_rs)
                .map(|(mut x, i)| {
                    x.scale(i);
                    x
                })
                .collect()
        }
        fn partial_products<S: BeaverSource<Self, Self, Self>>(
            x: Vec<Self>,
            src: &mut S,
        ) -> Vec<Self> {
            let n = x.len();
            let m: Vec<Self> = (0..(n + 1)).map(|_| rand::<F>()).collect();
            let m_inv = Self::batch_inv(m.clone(), src);
            let mx = Self::batch_mul(m[..n].iter().cloned().collect(), x, src);
            let mxm = Self::batch_mul(mx, m_inv[1..].iter().cloned().collect(), src);
            let mut mxm_pub = Self::batch_open(mxm);
            for i in 1..mxm_pub.len() {
                let last = mxm_pub[i - 1];
                mxm_pub[i] *= &last;
            }
            let m0 = vec![m[0]; n];
            let mms = Self::batch_mul(m0, m_inv[1..].iter().cloned().collect(), src);
            let mut mms_inv = Self::batch_inv(mms, src);
            //let mms_pub = Self::batch_open(mms);
            for i in 0..mxm_pub.len() {
                mms_inv[i].scale(&mxm_pub[i]);
            }
            debug_assert!(mxm_pub.len() == n);
            mms_inv
        }
        fn univariate_div_qr<'a>(
            num: DenseOrSparsePolynomial<Self>,
            den: DenseOrSparsePolynomial<F>,
        ) -> Option<(DensePolynomial<Self>, DensePolynomial<Self>)> {
            let num = Self::poly_share(num);
            let den = Self::poly_share2(den);
            num.divide_with_q_and_r(&den)
                .map(|(q, r)| (Self::d_poly_unshare(q, t()), Self::d_poly_unshare(r, t())))
        }
    }

    /// Yields a t-share of a random r.
    ///
    /// Stubbed b/c it can be pre-processed.
    ///
    /// Protocol 3.
    pub fn rand<F: Field>() -> GszFieldShare<F> {
        GszFieldShare {
            val: F::one(),
            degree: t(),
        }
    }

    /// Yields two shares of a random `r`, one of degree t, one of degree 2t
    ///
    /// Stubbed b/c it can be pre-processed.
    ///
    /// Protocol 4.
    pub fn double_rand<F: Field>() -> (GszFieldShare<F>, GszFieldShare<F>) {
        (
            GszFieldShare {
                val: F::one(),
                degree: t(),
            },
            GszFieldShare {
                val: F::one(),
                degree: 2 * t(),
            },
        )
    }

    pub fn batch_double_rand<F: Field>(n: usize) -> (Vec<GszFieldShare<F>>, Vec<GszFieldShare<F>>) {
        (0..n).map(|_| double_rand()).unzip()
    }

    pub fn check_accumulated_field_products<F: FftField>() {
        let to_check = take_types::<GszFieldTriple<F>>();
        check_field_products(to_check);
    }
    pub fn check_field_products<F: FftField>(to_check: Vec<GszFieldTriple<F>>) {
        if to_check.len() > 0 {
            let timer = start_timer!(|| format!("Product check: {}", to_check.len()));
            debug!("Open Field: {} checks", to_check.len());
            let mut xs = Vec::new();
            let mut ys = Vec::new();
            let mut zs = Vec::new();
            for GszFieldTriple(x, y, z) in to_check {
                xs.push(x);
                ys.push(y);
                zs.push(z);
            }
            hadamard_check(xs, ys, zs);
            end_timer!(timer);
        }
    }

    /// Open a t-share.
    pub fn open<F: FftField>(s: &GszFieldShare<F>) -> F {
        check_accumulated_field_products::<F>();
        let shares = Net::broadcast(&s.val);
        open_degree_vec(shares, s.degree)
    }

    fn open_degree_vec<F: FftField>(mut shares: Vec<F>, d: usize) -> F {
        //let build_domain_timer = start_timer!(|| "domain");
        let domain = domain::<F>();
        //end_timer!(build_domain_timer);
        //let ifft_timer = start_timer!(|| "ifft");
        domain.ifft_in_place(&mut shares);
        //end_timer!(ifft_timer);
        //let eval_timer = start_timer!(|| "polyeval");
        let p = ark_poly::univariate::DensePolynomial::from_coefficients_vec(shares);
        assert!(
            p.degree() <= d,
            "Polynomial\n{:?}\nhas degree {} (> degree bound {})",
            p,
            p.degree(),
            d
        );
        let r = p.evaluate(&F::zero());
        //end_timer!(eval_timer);
        r
    }

    /// Given
    /// * A share `share`
    /// * A function over plain data, `f`
    ///
    /// 1. Opens the share to King.
    /// 2. King performs the function.
    /// 3. King reshares the result.
    pub fn king_compute<F: FftField, Func: FnOnce(F) -> F>(
        share: &GszFieldShare<F>,
        new_degree: usize,
        f: Func,
    ) -> GszFieldShare<F> {
        let king_answer = Net::send_to_king(&share.val).map(|shares| {
            let n = shares.len();
            let value = open_degree_vec(shares, share.degree);
            let output = f(value);
            // TODO: randomize
            vec![output; n]
        });
        let from_king = Net::recv_from_king(king_answer);
        GszFieldShare {
            degree: new_degree,
            val: from_king,
        }
    }

    /// Given
    /// * Shares `share`
    /// * A function over plain data, `f`
    ///
    /// 1. Opens the share to King.
    /// 2. King performs the function.
    /// 3. King reshares the result.
    pub fn batch_king_compute<F: FftField, Func: Fn(F) -> F>(
        shares: &[GszFieldShare<F>],
        new_degree: usize,
        f: Func,
    ) -> Vec<GszFieldShare<F>> {
        let values: Vec<F> = shares.iter().map(|s| s.val).collect();
        let king_answer = Net::send_to_king(&values).map(|all_shares| {
            let kc_timer = start_timer!(|| format!("King computation"));
            let n = all_shares.len();
            let mut outputs = vec![Vec::new(); n];
            for i in 0..all_shares[0].len() {
                let these_shares: Vec<F> = all_shares.iter().map(|s| s[i]).collect();
                let value = open_degree_vec(these_shares, shares[i].degree);
                let output = f(value);
                // TODO: randomize
                outputs.iter_mut().for_each(|o| o.push(output));
            }
            assert_eq!(outputs.len(), all_shares.len());
            assert_eq!(outputs[0].len(), all_shares[0].len());
            end_timer!(kc_timer);
            outputs
        });
        let from_king = Net::recv_from_king(king_answer);
        from_king
            .into_iter()
            .map(|from_king| GszFieldShare {
                degree: new_degree,
                val: from_king,
            })
            .collect()
    }

    /// Generate a random coin, unknown to all parties until now.
    ///
    /// Protocol 6.
    pub fn coin<F: FftField>() -> F {
        open(&rand())
    }

    /// Multiply shares, using king
    ///
    /// Protocol 8.
    pub fn mult<F: FftField>(
        x: GszFieldShare<F>,
        y: &GszFieldShare<F>,
        queue_check: bool,
    ) -> GszFieldShare<F> {
        let (r, r2) = double_rand::<F>();
        let mut x_cp = x.clone();
        x_cp.val *= y.val;
        x_cp.degree *= 2;
        x_cp.val += r2.val;
        // king just reduces the sharing degree
        let mut shift_res = king_compute(&x_cp, x_cp.degree / 2, |r| r);
        shift_res.val -= r.val;
        if queue_check {
            let triple = GszFieldTriple(x, y.clone(), shift_res);
            add_type(triple);
        }
        shift_res
    }

    /// Multiply shares, using king
    ///
    /// Protocol 8.
    pub fn batch_mult<F: FftField>(
        x: Vec<GszFieldShare<F>>,
        y: &[GszFieldShare<F>],
        queue_check: bool,
    ) -> Vec<GszFieldShare<F>> {
        let timer = start_timer!(|| format!("Batch mult: {}", x.len()));
        let n = x.len();
        let d = x[0].degree;
        assert_eq!(x.len(), y.len());
        let (r, r2) = batch_double_rand::<F>(n);
        let mut x_cp = x.clone();
        for ((x, y), r2) in x_cp.iter_mut().zip(y).zip(r2) {
            assert_eq!(x.degree, d);
            x.val *= y.val;
            x.degree *= 2;
            x.val += r2.val;
        }
        // king just reduces the sharing degree
        let kc_timer = start_timer!(|| format!("King compute wrapper"));
        let mut shift_res = batch_king_compute(&x_cp, x_cp[0].degree / 2, |r| r);
        end_timer!(kc_timer);
        for (shift_res, r) in shift_res.iter_mut().zip(r) {
            shift_res.val -= r.val;
        }
        if queue_check {
            let triples: Vec<_> = x
                .into_iter()
                .zip(y)
                .zip(&shift_res)
                .map(|((x, y), z)| GszFieldTriple(x, y.clone(), z.clone()))
                .collect();
            add_types(triples);
        }
        end_timer!(timer);
        shift_res
    }

    /// Convert a hadamard check into an IP check
    ///
    /// Protocol 13.
    pub fn hadamard_check<F: FftField>(
        mut xs: Vec<GszFieldShare<F>>,
        ys: Vec<GszFieldShare<F>>,
        zs: Vec<GszFieldShare<F>>,
    ) {
        let r = coin::<F>();
        let mut rzs_sum = GszFieldShare::from_public(F::zero());
        let mut r_i = F::one();
        for (x, mut z) in xs.iter_mut().zip(zs) {
            x.scale(&r_i);
            z.scale(&r_i);
            rzs_sum.add(&z);
            r_i *= &r;
        }
        ip_check(xs, ys, rzs_sum);
    }

    /// Compress two inner product checks into one.
    ///
    /// Protocol 12.
    pub fn ip_compress<F: FftField>(
        xs1: Vec<GszFieldShare<F>>,
        ys1: Vec<GszFieldShare<F>>,
        ip1: GszFieldShare<F>,
        xs2: Vec<GszFieldShare<F>>,
        ys2: Vec<GszFieldShare<F>>,
        ip2: GszFieldShare<F>,
    ) -> (
        Vec<GszFieldShare<F>>,
        Vec<GszFieldShare<F>>,
        GszFieldShare<F>,
    ) {
        let n = xs1.len();
        debug_assert_eq!(n, xs1.len());
        debug_assert_eq!(n, xs2.len());
        debug_assert_eq!(n, ys1.len());
        debug_assert_eq!(n, ys2.len());
        // View xs1 as a vector of polynomials evaluated at 1
        // View xs2 as a vector the same polynomials evaluated at 2
        // This is a vector of lines.
        // xs_m holds the slopes.
        // xs_b holds the y intercepts.
        let xs_m: Vec<GszFieldShare<F>> = (0..n)
            .map(|i| {
                let mut t = xs2[i];
                t.sub(&xs1[i]);
                t
            })
            .collect();
        let xs_b: Vec<GszFieldShare<F>> = (0..n)
            .map(|i| {
                let mut t = xs1[i];
                t.sub(&xs_m[i]);
                t
            })
            .collect();
        // Compute xs3 as a vector of the lines evaluated at 3
        let xs3: Vec<GszFieldShare<F>> = (0..n)
            .map(|i| {
                // x3 = m + x2
                let mut t = xs2[i];
                t.add(&xs_m[i]);
                t
            })
            .collect();

        // Same for ys...
        let ys_m: Vec<GszFieldShare<F>> = (0..n)
            .map(|i| {
                let mut t = ys2[i];
                t.sub(&ys1[i]);
                t
            })
            .collect();
        let ys_b: Vec<GszFieldShare<F>> = (0..n)
            .map(|i| {
                let mut t = ys1[i];
                t.sub(&ys_m[i]);
                t
            })
            .collect();
        let ys3: Vec<GszFieldShare<F>> = (0..n)
            .map(|i| {
                // y3 = m + y2
                let mut t = ys2[i];
                t.add(&ys_m[i]);
                t
            })
            .collect();

        // Compute ip3 from scratch.
        let ip3 = ip_compute(&xs3, &ys3);

        let r = coin::<F>();

        // Now, we want to evaluat the x-functions, y-functions, and ip-function at r.
        // The x-functions and y-functions are defined as above (lines)
        let xs_r: Vec<GszFieldShare<F>> = (0..n)
            .map(|i| {
                let mut t = xs_m[i];
                t.scale(&r);
                t.add(&xs_b[i]);
                t
            })
            .collect();
        let ys_r: Vec<GszFieldShare<F>> = (0..n)
            .map(|i| {
                let mut t = ys_m[i];
                t.scale(&r);
                t.add(&ys_b[i]);
                t
            })
            .collect();
        // The ip-function is a parabola
        // We need the lagrange basis on 1, 2, 3. It is:
        // f_1(X) = (X-2)(X-3)/2
        // f_2(X) = (X-1)(X-3)/-1
        // f_3(X) = (X-1)(X-2)/2
        let ip_r = {
            // evaluate basis polynomials at 1, 2, 3
            let f_1 = (r - F::from(2u8)) * (r - F::from(3u8)) / F::from(2u8);
            let f_2 = -(r - F::from(1u8)) * (r - F::from(3u8));
            let f_3 = (r - F::from(1u8)) * (r - F::from(2u8)) / F::from(2u8);
            let degree = (&[ip1.degree, ip2.degree, ip3.degree])
                .iter()
                .max()
                .unwrap()
                .clone();
            GszFieldShare {
                degree,
                val: f_1 * ip1.val + f_2 * ip2.val + f_3 * ip3.val,
            }
        };
        (xs_r, ys_r, ip_r)
    }

    /// Check an IP, recursively shrinking it
    ///
    /// Protocols 14, 15
    pub fn ip_check<F: FftField>(
        mut xs: Vec<GszFieldShare<F>>,
        mut ys: Vec<GszFieldShare<F>>,
        mut ip: GszFieldShare<F>,
    ) {
        // print_list!(xs);
        // print_list!(ys);
        // dd!(ip);
        debug_assert_eq!(xs.len(), ys.len());
        while xs.len() > 1 {
            if xs.len() % 2 == 1 {
                xs.push(GszFieldShare::from_public(F::zero()));
                ys.push(GszFieldShare::from_public(F::zero()));
            }
            let n = xs.len() / 2;
            let xs_r = xs.split_off(n);
            let xs_l = xs;
            let ys_r = ys.split_off(n);
            let ys_l = ys;
            let ip_l = ip_compute(&xs_l, &ys_l);
            let ip_r = {
                let mut t = ip;
                t.sub(&ip_l);
                t
            };
            //     print_list!(xs_l);
            //     print_list!(ys_l);
            //     dd!(ip_l);
            //     print_list!(xs_r);
            //     print_list!(ys_r);
            //     dd!(ip_r);
            let (compressed_xs, compressed_ys, compressed_ip) =
                ip_compress(xs_l, ys_l, ip_l, xs_r, ys_r, ip_r);
            xs = compressed_xs;
            ys = compressed_ys;
            ip = compressed_ip;
        }
        let xr = rand::<F>();
        let x = xs.pop().unwrap();
        let yr = rand::<F>();
        let y = ys.pop().unwrap();
        let ip_r = mult(xr.clone(), &yr, false);
        let x_blind = mult(x, &xr, false);
        let y_blind = mult(y, &yr, false);
        let ip_blind = mult(ip, &ip_r, false);
        let x = open(&x_blind);
        let y = open(&y_blind);
        let z = open(&ip_blind);
        assert_eq!(x * &y, z);
    }

    pub fn ip_compute<F: FftField>(
        xs: &[GszFieldShare<F>],
        ys: &[GszFieldShare<F>],
    ) -> GszFieldShare<F> {
        debug_assert!(xs.iter().all(|x| x.degree <= t()));
        debug_assert!(ys.iter().all(|x| x.degree <= t()));
        assert_eq!(xs.len(), ys.len());
        let mut acc = F::zero();
        let mut degree = 0;
        for (x, y) in xs.iter().zip(ys) {
            acc += x.val * &y.val;
            degree = std::cmp::max(degree, 2 * std::cmp::max(x.degree, y.degree));
        }
        let (r, r2) = double_rand::<F>();
        acc += r2.val;
        let acc_share = GszFieldShare { val: acc, degree };
        let mut shifted_result = king_compute(&acc_share, degree / 2, |r| r);
        shifted_result.sub(&r);
        shifted_result
    }

    pub struct GszFieldTriple<F: Field>(
        pub GszFieldShare<F>,
        pub GszFieldShare<F>,
        pub GszFieldShare<F>,
    );
}

pub use field::GszFieldShare;

pub mod group {
    use super::super::group::GroupShare;
    use super::*;
    use ark_ec::group::Group;
    use std::marker::PhantomData;

    #[derive(Derivative)]
    #[derivative(
        Clone(bound = "T: Clone"),
        Copy(bound = "T: Copy"),
        PartialEq(bound = "T: PartialEq"),
        Eq(bound = "T: Eq"),
        PartialOrd(bound = "T: PartialOrd"),
        Ord(bound = "T: Ord"),
        Hash(bound = "T: Hash")
    )]
    pub struct GszGroupShare<T, M> {
        pub val: T,
        pub degree: usize,
        pub _phants: PhantomData<M>,
    }
    impl<T: Group, M> Display for GszGroupShare<T, M> {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.val)
        }
    }
    impl<T: Group, M> Debug for GszGroupShare<T, M> {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "{:?}", self.val)
        }
    }
    impl<T: Group, M> ToBytes for GszGroupShare<T, M> {
        fn write<W: Write>(&self, _writer: W) -> io::Result<()> {
            unimplemented!("write")
        }
    }
    impl<T: Group, M> FromBytes for GszGroupShare<T, M> {
        fn read<R: Read>(_reader: R) -> io::Result<Self> {
            unimplemented!("read")
        }
    }
    impl<T: Group, M> CanonicalSerialize for GszGroupShare<T, M> {
        fn serialize<W: Write>(&self, _writer: W) -> Result<(), SerializationError> {
            unimplemented!("serialize")
        }
        fn serialized_size(&self) -> usize {
            unimplemented!("serialized_size")
        }
    }
    impl<T: Group, M> CanonicalSerializeWithFlags for GszGroupShare<T, M> {
        fn serialize_with_flags<W: Write, F: Flags>(
            &self,
            _writer: W,
            _flags: F,
        ) -> Result<(), SerializationError> {
            unimplemented!("serialize_with_flags")
        }

        fn serialized_size_with_flags<F: Flags>(&self) -> usize {
            unimplemented!("serialized_size_with_flags")
        }
    }
    impl<T: Group, M> CanonicalDeserialize for GszGroupShare<T, M> {
        fn deserialize<R: Read>(_reader: R) -> Result<Self, SerializationError> {
            unimplemented!("deserialize")
        }
    }
    impl<T: Group, M> CanonicalDeserializeWithFlags for GszGroupShare<T, M> {
        fn deserialize_with_flags<R: Read, F: Flags>(
            _reader: R,
        ) -> Result<(Self, F), SerializationError> {
            unimplemented!("deserialize_with_flags")
        }
    }
    impl<T: Group, M> UniformRand for GszGroupShare<T, M> {
        fn rand<R: Rng + ?Sized>(_rng: &mut R) -> Self {
            todo!()
        }
    }

    impl<G: Group, M: Send + 'static + Msm<G, G::ScalarField>> Reveal for GszGroupShare<G, M> {
        type Base = G;

        fn reveal(self) -> G {
            M::pre_reveal_check();
            open(&self)
        }
        fn from_public(f: G) -> Self {
            Self {
                val: f,
                degree: t(),
                _phants: PhantomData::default(),
            }
        }
        fn from_add_shared(_f: G) -> Self {
            unimplemented!("from_add_shared")
        }
        fn unwrap_as_public(self) -> G {
            self.val
        }
        fn king_share<R: Rng>(f: Self::Base, _rng: &mut R) -> Self {
            let fs = vec![f; Net::n_parties()];
            let king_f = Net::recv_from_king(if Net::am_king() { Some(fs) } else { None });
            Self {
                val: king_f,
                degree: t(),
                _phants: Default::default(),
            }
        }
        fn king_share_batch<R: Rng>(f: Vec<Self::Base>, _rng: &mut R) -> Vec<Self> {
            let fs = vec![f; Net::n_parties()];
            let king_fs = Net::recv_from_king(if Net::am_king() { Some(fs) } else { None });
            king_fs
                .into_iter()
                .map(|king_f| Self {
                    val: king_f,
                    degree: t(),
                    _phants: Default::default(),
                })
                .collect()
        }
    }

    impl<G: Group, M: Msm<G, G::ScalarField>> GroupShare<G> for GszGroupShare<G, M> {
        type FieldShare = GszFieldShare<G::ScalarField>;

        fn add(&mut self, other: &Self) -> &mut Self {
            self.val += &other.val;
            self
        }

        fn sub(&mut self, other: &Self) -> &mut Self {
            self.val -= &other.val;
            self
        }

        fn scale_pub_scalar(&mut self, scalar: &G::ScalarField) -> &mut Self {
            self.val *= *scalar;
            self
        }

        fn scale_pub_group(mut base: G, scalar: &Self::FieldShare) -> Self {
            base *= scalar.val;
            Self {
                val: base,
                degree: scalar.degree,
                _phants: PhantomData::default(),
            }
        }

        fn shift(&mut self, other: &G) -> &mut Self {
            self.val += other;
            self
        }

        fn scale<S: BeaverSource<Self, Self::FieldShare, Self>>(
            self,
            other: Self::FieldShare,
            _source: &mut S,
        ) -> Self {
            mult(&other, self, true)
        }

        fn multi_scale_pub_group(bases: &[G], scalars: &[Self::FieldShare]) -> Self {
            let degree = if scalars.len() > 0 {
                scalars[0].degree
            } else {
                0
            };
            assert!(scalars.iter().all(|s| s.degree == degree));
            let s_t = start_timer!(|| "Collecting scalar shares");
            let scalars: Vec<G::ScalarField> = scalars.into_iter().map(|s| s.val.clone()).collect();
            end_timer!(s_t);
            let msm_t = start_timer!(|| "MSM");
            let msm = M::msm(bases, &scalars);
            end_timer!(msm_t);
            Self {
                val: msm,
                degree,
                _phants: Default::default(),
            }
        }
    }

    /// Yields a t-share of a random r.
    ///
    /// Stubbed b/c it can be pre-processed.
    ///
    /// Protocol 3.
    pub fn rand<G: Group, M>() -> GszGroupShare<G, M> {
        GszGroupShare {
            val: G::zero(),
            degree: t(),
            _phants: Default::default(),
        }
    }

    /// Yields two shares of a random `r`, one of degree t, one of degree 2t
    ///
    /// Stubbed b/c it can be pre-processed.
    ///
    /// Protocol 4.
    pub fn double_rand<G: Group, M>() -> (GszGroupShare<G, M>, GszGroupShare<G, M>) {
        (
            GszGroupShare {
                val: G::zero(),
                degree: t(),
                _phants: Default::default(),
            },
            GszGroupShare {
                val: G::zero(),
                degree: 2 * t(),
                _phants: Default::default(),
            },
        )
    }

    pub struct GszGroupTriple<G: Group, M>(
        pub GszFieldShare<G::ScalarField>,
        pub GszGroupShare<G, M>,
        pub GszGroupShare<G, M>,
    );

    /// Open a t-share.
    pub fn open<G: Group, M: Send + 'static>(s: &GszGroupShare<G, M>) -> G {
        let shares = Net::broadcast(&s.val);
        open_degree_vec(shares, s.degree)
    }

    fn open_degree_vec<G: Group>(shares: Vec<G>, d: usize) -> G {
        let domain = domain::<G::ScalarField>();
        let n = Net::n_parties();
        let n_inv = G::ScalarField::from(n as u32).inverse().unwrap();
        let w = domain.element(1);
        let w_inv = w.inverse().unwrap();
        // w^{-i}
        let mut w_inv_i = G::ScalarField::one();
        let coeffs: Vec<G> = (0..n)
            .map(|i| {
                let mut coeff = G::zero();
                // 1/N * w^{-ij}
                let mut w_inv_ij = n_inv;
                for _j in 0..n {
                    coeff += shares[i].mul(&w_inv_ij);
                    w_inv_ij *= &w_inv_i;
                }
                w_inv_i *= &w_inv;
                coeff
            })
            .collect();
        assert_eq!(coeffs.len(), n);
        for i in d + 1..n {
            assert!(
                coeffs[i].is_zero(),
                "Non-identity coeffs {} ({}), when expecting a degree <= {} poly",
                i,
                coeffs[i],
                d
            );
        }
        coeffs[0]
    }

    /// Given
    /// * A share `share`
    /// * A function over plain data, `f`
    ///   * which also outputs a sharing degree.
    ///
    /// 1. Opens the share to King.
    /// 2. King performs the function.
    /// 3. King reshares the result.
    pub fn king_compute<G: Group, M, Func: FnOnce(G) -> G>(
        share: &GszGroupShare<G, M>,
        new_degree: usize,
        f: Func,
    ) -> GszGroupShare<G, M> {
        let king_answer = Net::send_to_king(&share.val).map(|shares| {
            let n = shares.len();
            let value = open_degree_vec(shares, share.degree);
            let output = f(value);
            // TODO: randomize
            vec![output; n]
        });
        let from_king = Net::recv_from_king(king_answer);
        GszGroupShare {
            degree: new_degree,
            val: from_king,
            _phants: Default::default(),
        }
    }
    /// Multiply shares, using king
    ///
    /// Protocol 8.
    pub fn mult<G: Group, M: Send + 'static>(
        x: &GszFieldShare<G::ScalarField>,
        y: GszGroupShare<G, M>,
        queue_check: bool,
    ) -> GszGroupShare<G, M> {
        let mut y_cp = y.clone();
        let (r, r2) = double_rand::<G, M>();
        y_cp.val *= x.val;
        y_cp.degree *= 2;
        y_cp.val += r2.val;
        // king just reduces the sharing degree
        let mut shift_res = king_compute(&y_cp, x.degree / 2, |r| r);
        shift_res.val -= r.val;
        if queue_check {
            let t = GszGroupTriple(x.clone(), y, shift_res);
            add_type(t);
        }
        shift_res
    }

    pub fn ip_compute<G: Group, M: Msm<G, G::ScalarField>>(
        xs: &[GszFieldShare<G::ScalarField>],
        ys: &[GszGroupShare<G, M>],
    ) -> GszGroupShare<G, M> {
        debug_assert!(xs.iter().all(|x| x.degree <= t()));
        debug_assert!(ys.iter().all(|x| x.degree <= t()));
        assert_eq!(xs.len(), ys.len());
        let mut acc = G::zero();
        let mut degree = 0;
        for (x, y) in xs.iter().zip(ys) {
            acc += y.val.mul(&x.val);
            degree = std::cmp::max(degree, 2 * std::cmp::max(x.degree, y.degree));
        }
        let (r, r2) = double_rand::<G, M>();
        acc += r2.val;
        let acc_share = GszGroupShare {
            val: acc,
            degree,
            _phants: Default::default(),
        };
        let mut shifted_result = king_compute(&acc_share, degree / 2, |r| r);
        shifted_result.sub(&r);
        shifted_result
    }

    /// Compress two inner product checks into one.
    ///
    /// Protocol 12.
    pub fn ip_compress<G: Group, M: Msm<G, G::ScalarField>>(
        xs1: Vec<GszFieldShare<G::ScalarField>>,
        ys1: Vec<GszGroupShare<G, M>>,
        ip1: GszGroupShare<G, M>,
        xs2: Vec<GszFieldShare<G::ScalarField>>,
        ys2: Vec<GszGroupShare<G, M>>,
        ip2: GszGroupShare<G, M>,
    ) -> (
        Vec<GszFieldShare<G::ScalarField>>,
        Vec<GszGroupShare<G, M>>,
        GszGroupShare<G, M>,
    ) {
        let n = xs1.len();
        debug_assert_eq!(n, xs1.len());
        debug_assert_eq!(n, xs2.len());
        debug_assert_eq!(n, ys1.len());
        debug_assert_eq!(n, ys2.len());
        // View xs1 as a vector of polynomials evaluated at 1
        // View xs2 as a vector the same polynomials evaluated at 2
        // This is a vector of lines.
        // xs_m holds the slopes.
        // xs_b holds the y intercepts.
        let xs_m: Vec<GszFieldShare<G::ScalarField>> = (0..n)
            .map(|i| {
                let mut t = xs2[i];
                t.sub(&xs1[i]);
                t
            })
            .collect();
        let xs_b: Vec<GszFieldShare<G::ScalarField>> = (0..n)
            .map(|i| {
                let mut t = xs1[i];
                t.sub(&xs_m[i]);
                t
            })
            .collect();
        // Compute xs3 as a vector of the lines evaluated at 3
        let xs3: Vec<GszFieldShare<G::ScalarField>> = (0..n)
            .map(|i| {
                // x3 = m + x2
                let mut t = xs2[i];
                t.add(&xs_m[i]);
                t
            })
            .collect();

        // Same for ys...
        let ys_m: Vec<GszGroupShare<G, M>> = (0..n)
            .map(|i| {
                let mut t = ys2[i];
                t.sub(&ys1[i]);
                t
            })
            .collect();
        let ys_b: Vec<GszGroupShare<G, M>> = (0..n)
            .map(|i| {
                let mut t = ys1[i];
                t.sub(&ys_m[i]);
                t
            })
            .collect();
        let ys3: Vec<GszGroupShare<G, M>> = (0..n)
            .map(|i| {
                // y3 = m + y2
                let mut t = ys2[i];
                t.add(&ys_m[i]);
                t
            })
            .collect();

        // Compute ip3 from scratch.
        let ip3 = ip_compute(&xs3, &ys3);

        let r = field::coin::<G::ScalarField>();

        // Now, we want to evaluat the x-functions, y-functions, and ip-function at r.
        // The x-functions and y-functions are defined as above (lines)
        let xs_r: Vec<GszFieldShare<G::ScalarField>> = (0..n)
            .map(|i| {
                let mut t = xs_m[i];
                t.scale(&r);
                t.add(&xs_b[i]);
                t
            })
            .collect();
        let ys_r: Vec<GszGroupShare<G, M>> = (0..n)
            .map(|i| {
                let mut t = ys_m[i];
                t.scale_pub_scalar(&r);
                t.add(&ys_b[i]);
                t
            })
            .collect();
        // The ip-function is a parabola
        // We need the lagrange basis on 1, 2, 3. It is:
        // f_1(X) = (X-2)(X-3)/2
        // f_2(X) = (X-1)(X-3)/-1
        // f_3(X) = (X-1)(X-2)/2
        let ip_r = {
            let one = G::ScalarField::from(1u8);
            let two = G::ScalarField::from(2u8);
            let three = G::ScalarField::from(3u8);
            // evaluate basis polynomials at 1, 2, 3
            let f_1 = (r - two) * (r - three) / two;
            let f_2 = -(r - one) * (r - three);
            let f_3 = (r - one) * (r - two) / two;
            debug_assert_eq!(ip1.degree, ip2.degree);
            debug_assert_eq!(ip2.degree, ip3.degree);
            GszGroupShare {
                degree: ip1.degree,
                val: ip1.val.mul(&f_1) + ip2.val.mul(&f_2) + ip3.val.mul(&f_3),
                _phants: Default::default(),
            }
        };
        (xs_r, ys_r, ip_r)
    }

    /// Check an IP, recursively shrinking it
    ///
    /// Protocols 14, 15
    pub fn ip_check<G: Group, M: Msm<G, G::ScalarField>>(
        mut xs: Vec<GszFieldShare<G::ScalarField>>,
        mut ys: Vec<GszGroupShare<G, M>>,
        mut ip: GszGroupShare<G, M>,
    ) {
        // print_list!(xs);
        // print_list!(ys);
        // dd!(ip);
        debug_assert_eq!(xs.len(), ys.len());
        while xs.len() > 1 {
            if xs.len() % 2 == 1 {
                xs.push(GszFieldShare::from_public(G::ScalarField::zero()));
                ys.push(GszGroupShare::from_public(G::zero()));
            }
            let n = xs.len() / 2;
            let xs_r = xs.split_off(n);
            let xs_l = xs;
            let ys_r = ys.split_off(n);
            let ys_l = ys;
            let ip_l = ip_compute(&xs_l, &ys_l);
            let ip_r = {
                let mut t = ip;
                t.sub(&ip_l);
                t
            };
            //     print_list!(xs_l);
            //     print_list!(ys_l);
            //     dd!(ip_l);
            //     print_list!(xs_r);
            //     print_list!(ys_r);
            //     dd!(ip_r);
            let (compressed_xs, compressed_ys, compressed_ip) =
                ip_compress(xs_l, ys_l, ip_l, xs_r, ys_r, ip_r);
            xs = compressed_xs;
            ys = compressed_ys;
            ip = compressed_ip;
        }
        let xr = field::rand::<G::ScalarField>();
        let x = xs.pop().unwrap();
        let yr = field::rand::<G::ScalarField>();
        let y = ys.pop().unwrap();
        let ip_r = field::mult(xr, &yr, false);
        let x_blind = field::mult(x, &xr, false);
        let y_blind = mult(&yr, y, false);
        let ip_blind = mult(&ip_r, ip, false);
        let x = field::open(&x_blind);
        let y = open(&y_blind);
        let z = open(&ip_blind);
        assert_eq!(y.mul(&x), z);
    }

    /// Convert a hadamard check into an IP check
    ///
    /// Protocol 13.
    pub fn hadamard_check<G: Group, M: Msm<G, G::ScalarField>>(
        mut xs: Vec<GszFieldShare<G::ScalarField>>,
        ys: Vec<GszGroupShare<G, M>>,
        zs: Vec<GszGroupShare<G, M>>,
    ) {
        let r = field::coin::<G::ScalarField>();
        let mut rzs_sum = GszGroupShare::from_public(G::zero());
        let mut r_i = G::ScalarField::one();
        for (x, mut z) in xs.iter_mut().zip(zs) {
            x.scale(&r_i);
            z.scale_pub_scalar(&r_i);
            rzs_sum.add(&z);
            r_i *= &r;
        }
        ip_check(xs, ys, rzs_sum);
    }

    pub fn check_accumulated_group_products<G: Group, M: Msm<G, G::ScalarField>>() {
        let to_check = take_types::<GszGroupTriple<G, M>>();
        check_group_products(to_check);
    }

    pub fn check_group_products<G: Group, M: Msm<G, G::ScalarField>>(
        to_check: Vec<GszGroupTriple<G, M>>,
    ) {
        if to_check.len() > 0 {
            let timer = start_timer!(|| format!("Group product checks: {}", to_check.len()));
            debug!("Open Group: {} checks", to_check.len());
            let mut xs = Vec::new();
            let mut ys = Vec::new();
            let mut zs = Vec::new();
            for GszGroupTriple(x, y, z) in to_check {
                xs.push(x);
                ys.push(y);
                zs.push(z);
            }
            hadamard_check(xs, ys, zs);
            end_timer!(timer);
        }
    }
}

pub use group::GszGroupShare;

// #[derive(Debug, Derivative)]
// #[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
// pub struct AdditiveAffineMsm<G: AffineCurve>(pub PhantomData<G>);
//
// impl<G: AffineCurve> Msm<G, G::ScalarField> for AdditiveAffineMsm<G> {
//     fn msm(bases: &[G], scalars: &[G::ScalarField]) -> G {
//         G::multi_scalar_mul(bases, scalars).into()
//     }
// }
//
// #[derive(Debug, Derivative)]
// #[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
// pub struct AdditiveProjectiveMsm<G: ProjectiveCurve>(pub PhantomData<G>);
//
// impl<G: ProjectiveCurve> Msm<G, G::ScalarField> for AdditiveProjectiveMsm<G> {
//     fn msm(bases: &[G], scalars: &[G::ScalarField]) -> G {
//         let bases: Vec<G::Affine> = bases.iter().map(|s| s.clone().into()).collect();
//         <G::Affine as AffineCurve>::multi_scalar_mul(&bases, scalars)
//     }
// }

macro_rules! groups_share {
    ($struct_name:ident, $affine:ident, $proj:ident, $aff_msm:ident, $proj_msm:ident) => {
        pub struct $struct_name<E: PairingEngine>(pub PhantomData<E>);

        impl<E: PairingEngine> AffProjShare<E::Fr, E::$affine, E::$proj> for $struct_name<E> {
            type FrShare = GszFieldShare<E::Fr>;
            type AffineShare = GszGroupShare<E::$affine, msm::$aff_msm<E>>;
            type ProjectiveShare = GszGroupShare<E::$proj, msm::$proj_msm<E>>;

            fn sh_aff_to_proj(g: Self::AffineShare) -> Self::ProjectiveShare {
                GszGroupShare {
                    val: g.val.into(),
                    degree: g.degree,
                    _phants: Default::default(),
                }
            }

            fn sh_proj_to_aff(g: Self::ProjectiveShare) -> Self::AffineShare {
                GszGroupShare {
                    val: g.val.into(),
                    degree: g.degree,
                    _phants: Default::default(),
                }
            }

            fn add_sh_proj_sh_aff(
                mut a: Self::ProjectiveShare,
                o: &Self::AffineShare,
            ) -> Self::ProjectiveShare {
                a.val.add_assign_mixed(&o.val);
                a
            }
            fn add_sh_proj_pub_aff(
                mut a: Self::ProjectiveShare,
                o: &E::$affine,
            ) -> Self::ProjectiveShare {
                a.val.add_assign_mixed(&o);
                a
            }
            fn add_pub_proj_sh_aff(_a: &E::$proj, _o: Self::AffineShare) -> Self::ProjectiveShare {
                unimplemented!()
            }
        }
    };
}

groups_share!(
    GszG1Share,
    G1Affine,
    G1Projective,
    GszG1AffineMsm,
    GszG1ProjectiveMsm
);
groups_share!(
    GszG2Share,
    G2Affine,
    G2Projective,
    GszG2AffineMsm,
    GszG2ProjectiveMsm
);

pub mod mul_field {
    use super::*;

    #[derive(Derivative)]
    #[derivative(
        Clone(bound = "T: Clone"),
        Copy(bound = "T: Copy"),
        PartialEq(bound = "T: PartialEq"),
        Eq(bound = "T: Eq"),
        PartialOrd(bound = "T: PartialOrd"),
        Ord(bound = "T: Ord"),
        Hash(bound = "T: Hash")
    )]
    pub struct MulFieldShare<T, S> {
        pub val: T,
        pub degree: usize,
        pub _phants: PhantomData<S>,
    }

    macro_rules! impl_basics_2_param {
        ($share:ident, $bound:ident) => {
            impl<T: $bound, M> Display for $share<T, M> {
                fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                    write!(f, "{}", self.val)
                }
            }
            impl<T: $bound, M> Debug for $share<T, M> {
                fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                    write!(f, "{:?}", self.val)
                }
            }
            impl<T: $bound, M> ToBytes for $share<T, M> {
                fn write<W: Write>(&self, _writer: W) -> io::Result<()> {
                    unimplemented!("write")
                }
            }
            impl<T: $bound, M> FromBytes for $share<T, M> {
                fn read<R: Read>(_reader: R) -> io::Result<Self> {
                    unimplemented!("read")
                }
            }
            impl<T: $bound, M> CanonicalSerialize for $share<T, M> {
                fn serialize<W: Write>(&self, _writer: W) -> Result<(), SerializationError> {
                    unimplemented!("serialize")
                }
                fn serialized_size(&self) -> usize {
                    unimplemented!("serialized_size")
                }
            }
            impl<T: $bound, M> CanonicalSerializeWithFlags for $share<T, M> {
                fn serialize_with_flags<W: Write, F: Flags>(
                    &self,
                    _writer: W,
                    _flags: F,
                ) -> Result<(), SerializationError> {
                    unimplemented!("serialize_with_flags")
                }

                fn serialized_size_with_flags<F: Flags>(&self) -> usize {
                    unimplemented!("serialized_size_with_flags")
                }
            }
            impl<T: $bound, M> CanonicalDeserialize for $share<T, M> {
                fn deserialize<R: Read>(_reader: R) -> Result<Self, SerializationError> {
                    unimplemented!("deserialize")
                }
            }
            impl<T: $bound, M> CanonicalDeserializeWithFlags for $share<T, M> {
                fn deserialize_with_flags<R: Read, F: Flags>(
                    _reader: R,
                ) -> Result<(Self, F), SerializationError> {
                    unimplemented!("deserialize_with_flags")
                }
            }
            impl<T: $bound, M> UniformRand for $share<T, M> {
                fn rand<R: Rng + ?Sized>(_rng: &mut R) -> Self {
                    todo!()
                    //Reveal::from_add_shared(<T as UniformRand>::rand(rng))
                }
            }
        };
    }

    impl_basics_2_param!(MulFieldShare, Field);

    impl<F: Field, S: PrimeField> Reveal for MulFieldShare<F, S> {
        type Base = F;

        fn reveal(self) -> F {
            open_mul_field(&self)
        }
        fn from_public(f: F) -> Self {
            Self {
                val: f,
                degree: t(),
                _phants: Default::default(),
            }
        }
        fn from_add_shared(_f: F) -> Self {
            unimplemented!()
        }
        fn unwrap_as_public(self) -> F {
            self.val
        }
    }

    impl<F: Field, S: PrimeField> FieldShare<F> for MulFieldShare<F, S> {
        fn map_homo<FF: Field, SS: FieldShare<FF>, Fun: Fn(F) -> FF>(self, _f: Fun) -> SS {
            unimplemented!()
        }

        fn add(&mut self, _other: &Self) -> &mut Self {
            unimplemented!("add for MulFieldShare")
        }

        fn scale(&mut self, other: &F) -> &mut Self {
            self.val *= other;
            self
        }

        fn shift(&mut self, _other: &F) -> &mut Self {
            unimplemented!("add for MulFieldShare")
        }

        fn mul<SS: BeaverSource<Self, Self, Self>>(self, other: Self, _source: &mut SS) -> Self {
            Self {
                val: self.val * other.val,
                degree: self.degree,
                _phants: Default::default(),
            }
        }

        fn inv<SS: BeaverSource<Self, Self, Self>>(mut self, _source: &mut SS) -> Self {
            self.val = self.val.inverse().unwrap();
            self
        }
        fn batch_mul<SS: BeaverSource<Self, Self, Self>>(
            mut xs: Vec<Self>,
            ys: Vec<Self>,
            _source: &mut SS,
        ) -> Vec<Self> {
            for (x, y) in xs.iter_mut().zip(ys.iter()) {
                x.val *= y.val;
            }
            xs
        }

        fn batch_inv<SS: BeaverSource<Self, Self, Self>>(
            xs: Vec<Self>,
            source: &mut SS,
        ) -> Vec<Self> {
            xs.into_iter().map(|x| x.inv(source)).collect()
        }
    }

    /// Open a t-share.
    pub fn open_mul_field<F: Field, S: PrimeField>(s: &MulFieldShare<F, S>) -> F {
        let shares = Net::broadcast(&s.val);
        open_degree_vec::<F, S>(shares, s.degree)
    }

    fn open_degree_vec<F: Field, S: PrimeField>(shares: Vec<F>, d: usize) -> F {
        let domain = domain::<S>();
        let n = Net::n_parties();
        let n_inv = S::from(n as u32).inverse().unwrap();
        let w = domain.element(1);
        let w_inv = w.inverse().unwrap();
        // w^{-i}
        let mut w_inv_i = S::one();
        let coeffs: Vec<F> = (0..n)
            .map(|i| {
                let mut coeff = F::one();
                // 1/N * w^{-ij}
                let mut w_inv_ij = n_inv;
                for _j in 0..n {
                    coeff *= shares[i].pow(&w_inv_ij.into_repr());
                    w_inv_ij *= &w_inv_i;
                }
                w_inv_i *= &w_inv;
                coeff
            })
            .collect();
        assert_eq!(coeffs.len(), n);
        for i in d + 1..n {
            assert!(
                coeffs[i].is_one(),
                "Non-one coeffs {} ({}), when expecting a degree <= {} poly",
                i,
                coeffs[i],
                d
            );
        }
        coeffs[0]
    }
}

#[derive(Debug, Derivative)]
#[derivative(
    Default(bound = ""),
    Clone(bound = ""),
    Copy(bound = ""),
    PartialEq(bound = "F: PartialEq"),
    Eq(bound = "F: Eq"),
    Hash(bound = "F: Hash")
)]
pub struct GszMulExtFieldShare<F: Field, S>(pub PhantomData<(F, S)>);

impl<F: Field, S: PrimeField> ExtFieldShare<F> for GszMulExtFieldShare<F, S> {
    type Ext = mul_field::MulFieldShare<F, S>;
    type Base = mul_field::MulFieldShare<F::BasePrimeField, S>;
}

#[derive(Debug, Derivative)]
#[derivative(
    Default(bound = ""),
    Clone(bound = ""),
    Copy(bound = ""),
    PartialEq(bound = "F: PartialEq"),
    Eq(bound = "F: Eq"),
    Hash(bound = "F: Hash")
)]
pub struct GszExtFieldShare<F: Field>(pub PhantomData<F>);

impl<F: Field> ExtFieldShare<F> for GszExtFieldShare<F> {
    // TODO: wrong!
    type Ext = mul_field::MulFieldShare<F, F::BasePrimeField>;
    type Base = GszFieldShare<F::BasePrimeField>;
}

#[derive(Debug, Derivative)]
#[derivative(
    Default(bound = ""),
    Clone(bound = ""),
    Copy(bound = ""),
    PartialEq(bound = "E::G1Affine: PartialEq"),
    Eq(bound = "E::G1Affine: Eq"),
    Hash(bound = "E::G1Affine: Hash")
)]
pub struct GszPairingShare<E: PairingEngine>(pub PhantomData<E>);

pub mod msm {
    use super::*;

    fn run_all_checks<E: PairingEngine>() {
        let t = start_timer!(|| "All opening checks");
        field::check_accumulated_field_products::<E::Fr>();
        group::check_accumulated_group_products::<E::G1Affine, GszG1AffineMsm<E>>();
        group::check_accumulated_group_products::<E::G2Affine, GszG2AffineMsm<E>>();
        group::check_accumulated_group_products::<E::G1Projective, GszG1ProjectiveMsm<E>>();
        group::check_accumulated_group_products::<E::G2Projective, GszG2ProjectiveMsm<E>>();
        end_timer!(t);
    }

    #[derive(Debug, Derivative)]
    #[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
    /// An EC-based MSM with a pre-reveal check.
    pub struct GszG1AffineMsm<E: PairingEngine>(pub PhantomData<E>);

    impl<E: PairingEngine> Msm<E::G1Affine, E::Fr> for GszG1AffineMsm<E> {
        fn msm(bases: &[E::G1Affine], scalars: &[E::Fr]) -> E::G1Affine {
            E::G1Affine::multi_scalar_mul(bases, scalars).into()
        }
        fn pre_reveal_check() {
            run_all_checks::<E>();
        }
    }
    #[derive(Debug, Derivative)]
    #[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
    /// An EC-based MSM with a pre-reveal check.
    pub struct GszG2AffineMsm<E: PairingEngine>(pub PhantomData<E>);
    impl<E: PairingEngine> Msm<E::G2Affine, E::Fr> for GszG2AffineMsm<E> {
        fn msm(bases: &[E::G2Affine], scalars: &[E::Fr]) -> E::G2Affine {
            E::G2Affine::multi_scalar_mul(bases, scalars).into()
        }
        fn pre_reveal_check() {
            run_all_checks::<E>();
        }
    }
    #[derive(Debug, Derivative)]
    #[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
    /// An EC-based MSM with a pre-reveal check.
    pub struct GszG1ProjectiveMsm<E: PairingEngine>(pub PhantomData<E>);

    impl<E: PairingEngine> Msm<E::G1Projective, E::Fr> for GszG1ProjectiveMsm<E> {
        fn msm(bases: &[E::G1Projective], scalars: &[E::Fr]) -> E::G1Projective {
            let bases: Vec<E::G1Affine> = bases.iter().map(|s| s.clone().into()).collect();
            <E::G1Affine as AffineCurve>::multi_scalar_mul(&bases, scalars)
        }
        fn pre_reveal_check() {
            run_all_checks::<E>();
        }
    }
    #[derive(Debug, Derivative)]
    #[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
    /// An EC-based MSM with a pre-reveal check.
    pub struct GszG2ProjectiveMsm<E: PairingEngine>(pub PhantomData<E>);
    impl<E: PairingEngine> Msm<E::G2Projective, E::Fr> for GszG2ProjectiveMsm<E> {
        fn msm(bases: &[E::G2Projective], scalars: &[E::Fr]) -> E::G2Projective {
            let bases: Vec<E::G2Affine> = bases.iter().map(|s| s.clone().into()).collect();
            <E::G2Affine as AffineCurve>::multi_scalar_mul(&bases, scalars)
        }
        fn pre_reveal_check() {
            run_all_checks::<E>();
        }
    }
}

#[derive(Debug, Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
/// An EC-based MSM with a pre-reveal check.
pub struct GszProjectiveMsm<G: ProjectiveCurve>(pub PhantomData<G>);

impl<G: ProjectiveCurve> Msm<G, G::ScalarField> for GszProjectiveMsm<G> {
    fn msm(bases: &[G], scalars: &[G::ScalarField]) -> G {
        let bases: Vec<G::Affine> = bases.iter().map(|s| s.clone().into()).collect();
        <G::Affine as AffineCurve>::multi_scalar_mul(&bases, scalars)
    }
}

impl<E: PairingEngine> PairingShare<E> for GszPairingShare<E> {
    type FrShare = GszFieldShare<E::Fr>;
    type FqShare = GszFieldShare<E::Fq>;
    type FqeShare = GszExtFieldShare<E::Fqe>;
    // Not a typo. We want a multiplicative subgroup.
    type FqkShare = GszMulExtFieldShare<E::Fqk, E::Fr>;
    type G1AffineShare = GszGroupShare<E::G1Affine, msm::GszG1AffineMsm<E>>;
    type G2AffineShare = GszGroupShare<E::G2Affine, msm::GszG2AffineMsm<E>>;
    type G1ProjectiveShare = GszGroupShare<E::G1Projective, msm::GszG1ProjectiveMsm<E>>;
    type G2ProjectiveShare = GszGroupShare<E::G2Projective, msm::GszG2ProjectiveMsm<E>>;
    type G1 = GszG1Share<E>;
    type G2 = GszG2Share<E>;
}

use lazy_static::lazy_static;
use log::debug;
use std::net::ToSocketAddrs;
use std::sync::Mutex;

use super::MpcVal;
use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{start_timer, end_timer, cfg_iter_mut};

use mpc_net;

lazy_static! {
    static ref CH: Mutex<FieldChannel> = Mutex::new(FieldChannel::default());
}

/// Macro for locking the FieldChannel singleton in the current scope.
#[macro_use]
macro_rules! get_ch {
    () => {
        CH.lock().expect("Poisoned FieldChannel")
    };
}

struct FieldChannel {
    base: mpc_net::FieldChannel,
}

impl std::default::Default for FieldChannel {
    fn default() -> Self {
        Self {
            base: mpc_net::FieldChannel::default(),
        }
    }
}

impl FieldChannel {
    fn connect<A1: ToSocketAddrs, A2: ToSocketAddrs>(
        &mut self,
        self_addr: A1,
        other_addr: A2,
        talk_first: bool,
    ) {
        self.base.connect(self_addr, other_addr, talk_first)
    }
    fn exchange<F: CanonicalSerialize + CanonicalDeserialize>(&mut self, f: F) -> F {
        let mut bytes_out = Vec::new();
        f.serialize(&mut bytes_out).unwrap();
        debug!("Exchange serde: {}", bytes_out.len());
        let bytes_in = self.base.exchange_bytes(&bytes_out).unwrap();
        println!("Exchange {}: {}", self.base.exchanges, bytes_in.len());
        debug!("Exchange serde: {:?}\nfor {:?}", bytes_out, bytes_in);
        F::deserialize(&bytes_in[..]).unwrap()
    }

    fn exchange_bytes(&mut self, f: Vec<u8>) -> Vec<u8> {
        self.base.exchange_bytes(&f).unwrap()
    }

    fn field_triple<F: Field>(&mut self) -> Triple<F, F, F> {
        //TODO
        if self.base.talk_first {
            (
                MpcVal::from_shared(F::from(1u8)),
                MpcVal::from_shared(F::from(1u8)),
                MpcVal::from_shared(F::from(1u8)),
            )
        } else {
            (
                MpcVal::from_shared(F::from(0u8)),
                MpcVal::from_shared(F::from(0u8)),
                MpcVal::from_shared(F::from(0u8)),
            )
        }
    }

    fn field_triples<F: Field>(
        &mut self,
        n: usize,
    ) -> (Vec<MpcVal<F>>, Vec<MpcVal<F>>, Vec<MpcVal<F>>) {
        let mut a = Vec::new();
        let mut b = Vec::new();
        let mut c = Vec::new();
        for _ in 0..n {
            let (x, y, z) = self.field_triple();
            a.push(x);
            b.push(y);
            c.push(z);
        }
        (a, b, c)
    }

    fn field_inverse_pairs<F: Field>(
        &mut self,
        n: usize,
    ) -> (Vec<MpcVal<F>>, Vec<MpcVal<F>>) {
        let (mut x, y, z) = self.field_triples(n);
        let z = self.field_batch_publicize(z);
        cfg_iter_mut!(x).zip(z).for_each(|(x, z)| x.val /= z.val);
        (x, y)
    }

    fn field_inv<F: Field>(&mut self, mut a: MpcVal<F>) -> MpcVal<F> {
        debug!("field ^ -1");
        if a.shared {
            // x * y = z
            // TODO: check...
            let (mut x, _y, _z) = self.field_triple();
            // a * x
            let ax = self.field_mul(x, a);
            let mut ax = self.field_publicize(ax);
            ax.val.inverse_in_place();
            // a^-1 = (a * x)^-1 * x
            x.val = x.val * ax.val;
            x
        } else {
            a.val.inverse_in_place();
            a
        }
    }

    fn field_batch_inv<F: Field>(&mut self, mut as_: Vec<MpcVal<F>>) -> Vec<MpcVal<F>> {
        debug!("field ^ -1");
        let a_shared = as_[0].shared;
        assert!(as_.iter().all(|a| a.shared == a_shared));
        if a_shared {
            // x * y = z
            // TODO: check...
            let (mut xs, _ys, _zs) = self.field_triples(as_.len());
            // a * x
            let axs = self.field_batch_mul(xs.clone(), as_);
            let mut axs = self.field_batch_publicize(axs);
            for (ax, x) in axs.iter_mut().zip(xs.iter_mut()) {
                ax.val.inverse_in_place();
                // a^-1 = (a * x)^-1 * x
                x.val = x.val * ax.val;
            }
            xs
        } else {
            for a in &mut as_ {
                a.val.inverse_in_place();
            }
            as_
        }
    }

    fn field_mul<F: Field>(&mut self, mut a: MpcVal<F>, b: MpcVal<F>) -> MpcVal<F> {
        debug!("field * field");
        if a.shared && b.shared {
            // x * y = z
            let (x, y, mut z) = self.field_triple();
            // x + a
            let xa = self.field_add(a, &x);
            let xa = self.field_publicize(xa);
            // y + b
            let yb = self.field_add(b, &y);
            let yb = self.field_publicize(yb);
            // xy - (x+a)y - x(y+b) + (x+a)(y+b) = ab
            z.val -= y.val * &xa.val;
            z.val -= x.val * &yb.val;
            if self.base.talk_first {
                z.val += xa.val * &yb.val;
            }
            z
        } else {
            a.val *= b.val;
            a.shared = a.shared || b.shared;
            a
        }
    }
    fn field_batch_mul<F: Field>(
        &mut self,
        mut a: Vec<MpcVal<F>>,
        mut b: Vec<MpcVal<F>>,
    ) -> Vec<MpcVal<F>> {
        debug!("batch field * field: {}", a.len());
        let start = start_timer!(|| "batch multiply");
        //TODO: consider parallel iteration
        let a_shared = a[0].shared;
        assert!(a.iter().all(|a| a.shared == a_shared));
        let b_shared = b[0].shared;
        assert!(b.iter().all(|a| a.shared == b_shared));
        let r = if a_shared && b_shared {
            // x * y = z
            let (xs, ys, mut zs) = self.field_triples(a.len());
            // xa = x + a
            for (a, x) in a.iter_mut().zip(xs.iter()) {
                a.val += x.val;
            }
            // yb = y + b
            for (b, y) in b.iter_mut().zip(ys.iter()) {
                b.val += y.val;
            }
            let start_net = start_timer!(|| "batch multiply: exchange");
            let xas = self.field_batch_publicize(a);
            let ybs = self.field_batch_publicize(b);
            end_timer!(start_net);
            // xy - (x+a)y - x(y+b) + (x+a)(y+b) = ab
            for i in 0..zs.len() {
                zs[i].val -= ys[i].val * &xas[i].val;
                zs[i].val -= xs[i].val * &ybs[i].val;
                if self.base.talk_first {
                    zs[i].val += xas[i].val * &ybs[i].val;
                }
            }
            zs
        } else {
            for i in 0..a.len() {
                a[i].val *= b[i].val;
                a[i].shared = a[i].shared || b[i].shared;
            }
            a
        };
        end_timer!(start);
        r
    }

    fn field_partial_products<F: Field>(
        &mut self,
        x: Vec<MpcVal<F>>,
    ) -> Vec<MpcVal<F>> {
        let n = x.len();
        let (m, m_inv) = self.field_inverse_pairs(n + 1);
        let mx = self.field_batch_mul(m[..n].iter().cloned().collect(), x);
        let mxm = self.field_batch_mul(mx, m_inv[1..].iter().cloned().collect());
        let mut mxm_pub = self.field_batch_publicize(mxm);
        for i in 1..mxm_pub.len() {
            let last = mxm_pub[i - 1].val;
            mxm_pub[i].val *= &last;
        }
        let m0 = vec![m[0]; n];
        let mms = self.field_batch_mul(m0, m_inv[1..].iter().cloned().collect());
        let mms_pub = self.field_batch_publicize(mms);
        for i in 1..mxm_pub.len() {
            mxm_pub[i].val /= mms_pub[i].val;
        }
        debug_assert!(mxm_pub.len() == n);
        mxm_pub
    }


    fn field_add<F: Field>(&mut self, mut a: MpcVal<F>, b: &MpcVal<F>) -> MpcVal<F> {
        match (a.shared, b.shared) {
            (true, true) | (false, false) => {
                a.val += &b.val;
                a
            }
            (true, false) => {
                if self.base.talk_first {
                    a.val += &b.val;
                }
                a
            }
            (false, true) => {
                a.shared = true;
                if self.base.talk_first {
                    a.val += &b.val;
                }
                a
            }
        }
    }

    #[allow(dead_code)]
    fn field_sub<F: Field>(&mut self, mut a: MpcVal<F>, b: &MpcVal<F>) -> MpcVal<F> {
        match (a.shared, b.shared) {
            (true, true) | (false, false) => {
                a.val -= &b.val;
                a
            }
            (true, false) => {
                if self.base.talk_first {
                    a.val -= &b.val;
                }
                a
            }
            (false, true) => {
                a.shared = true;
                if self.base.talk_first {
                    a.val -= &b.val;
                }
                a
            }
        }
    }

    fn field_publicize<F: Field>(&mut self, a: MpcVal<F>) -> MpcVal<F> {
        assert!(a.shared);
        let mut other_val = self.exchange(a.val.clone());
        other_val += a.val;
        MpcVal::from_public(other_val)
    }

    fn field_batch_publicize<F: Field>(&mut self, mut a: Vec<MpcVal<F>>) -> Vec<MpcVal<F>> {
        assert!(a.iter().all(|a| a.shared));
        let mut bytes_out = Vec::new();
        for a in &a {
            a.val.serialize(&mut bytes_out).unwrap();
        }
        let bytes_per_elem = bytes_out.len() / a.len();
        let bytes_in = self.exchange_bytes(bytes_out);
        assert_eq!(a.len() * bytes_per_elem, bytes_in.len());
        //println!("Batch pub: {}, {} bytes", a.len(), bytes_out
        for (i, a) in a.iter_mut().enumerate() {
            a.shared = false;
            a.val +=
                F::deserialize(&bytes_in[i * bytes_per_elem..(i + 1) * bytes_per_elem]).unwrap();
        }
        a
    }

    fn curve_scalar_triple<G: ProjectiveCurve>(&mut self) -> Triple<G, G::ScalarField, G> {
        let (fa, fb, fc) = self.field_triple();
        let mut ca = MpcVal::from_shared(G::prime_subgroup_generator());
        ca.val *= fa.val;
        let mut cc = MpcVal::from_shared(G::prime_subgroup_generator());
        cc.val *= fc.val;
        (ca, fb, cc)
    }

    fn curve_mul<G: ProjectiveCurve>(
        &mut self,
        mut a: MpcVal<G>,
        b: MpcVal<G::ScalarField>,
    ) -> MpcVal<G> {
        debug!("field * curve");
        if a.shared && b.shared {
            // x * y = z
            let (mut x, y, mut z) = self.curve_scalar_triple();
            // x + a
            let xa = self.curve_add(a, &x);
            let mut xa = self.curve_publicize(xa);
            // y + b
            let yb = self.field_add(b, &y);
            let yb = self.field_publicize(yb);
            let mut ybxa = xa.clone();
            ybxa.val *= yb.val.clone();
            // (y + b) * x
            x.val *= yb.val;
            // y * (x + a)
            xa.val *= y.val;
            // (y + b) * (x + a)
            z.val -= xa.val;
            z.val -= x.val;
            if self.base.talk_first {
                z.val += ybxa.val;
            }
            z
        } else {
            a.val *= b.val;
            a.shared = a.shared || b.shared;
            a
        }
    }

    fn curve_add<F: ProjectiveCurve>(&mut self, mut a: MpcVal<F>, b: &MpcVal<F>) -> MpcVal<F> {
        match (a.shared, b.shared) {
            (true, true) | (false, false) => {
                a.val += &b.val;
                a
            }
            (true, false) => {
                if self.base.talk_first {
                    a.val += &b.val;
                }
                a
            }
            (false, true) => {
                a.shared = true;
                if self.base.talk_first {
                    a.val += &b.val;
                }
                a
            }
        }
    }

    #[allow(dead_code)]
    fn curve_sub<F: ProjectiveCurve>(&mut self, mut a: MpcVal<F>, b: &MpcVal<F>) -> MpcVal<F> {
        match (a.shared, b.shared) {
            (true, true) | (false, false) => {
                a.val -= &b.val;
                a
            }
            (true, false) => {
                if self.base.talk_first {
                    a.val -= &b.val;
                }
                a
            }
            (false, true) => {
                a.shared = true;
                if self.base.talk_first {
                    a.val -= &b.val;
                }
                a
            }
        }
    }

    fn curve_publicize<F: ProjectiveCurve>(&mut self, a: MpcVal<F>) -> MpcVal<F> {
        assert!(a.shared);
        let mut other_val = self.exchange(a.val.clone());
        other_val += a.val;
        MpcVal::from_public(other_val)
    }

    fn pairing_triple<E: PairingEngine>(&mut self) -> Triple<E::G1Projective, E::G2Projective, E::Fqk> {
        let (fa, fb, fc) = self.field_triple();
        let mut g1a = MpcVal::from_public(E::G1Projective::prime_subgroup_generator());
        g1a.val *= fa.val;
        let mut g2b = MpcVal::from_public(E::G2Projective::prime_subgroup_generator());
        g2b.val *= fb.val;
        let mut g1c = MpcVal::from_public(E::G1Projective::prime_subgroup_generator());
        g1c.val *= fc.val;
        let gtc = MpcVal::from_shared(E::pairing(
            g1c.val,
            E::G2Projective::prime_subgroup_generator(),
        ));

        (g1a, g2b, gtc)
    }

    fn pairing<E: PairingEngine>(
        &mut self,
        a: MpcVal<E::G1Projective>,
        b: MpcVal<E::G2Projective>,
    ) -> MpcVal<E::Fqk> {
        debug!("curve * curve");
        if a.shared && b.shared {
            // x * y = z
            let (x, y, mut z) = self.pairing_triple::<E>();
            // x + a
            let xa = self.curve_add(a, &x);
            let xa = self.curve_publicize(xa);
            // y + b
            let yb = self.curve_add(b, &y);
            let yb = self.curve_publicize(yb);
            let xayb = MpcVal::from_public(E::pairing(xa.val, yb.val));
            let xay = MpcVal::from_shared(E::pairing(xa.val, y.val));
            let xyb = MpcVal::from_shared(E::pairing(x.val, yb.val));
            // (y + b) * (x + a)
            z.val /= xay.val;
            z.val /= xyb.val;
            if self.base.talk_first {
                z.val *= xayb.val;
            }
            z
        } else {
            MpcVal::new(E::pairing(a.val, b.val), a.shared || b.shared)
        }
    }
}

/// Initialize the MPC
pub fn init<A1: ToSocketAddrs, A2: ToSocketAddrs>(self_: A1, peer: A2, talk_first: bool) {
    let mut ch = get_ch!();
    assert!(
        ch.base.stream.is_none(),
        "FieldChannel should no be re-intialized. Did you call init(..) twice?"
    );
    ch.connect(self_, peer, talk_first);
}

/// Exchange serializable element with the other party.
pub fn exchange<F: CanonicalSerialize + CanonicalDeserialize>(f: F) -> F {
    get_ch!().exchange(f)
}

/// Exchange serializable element with the other party.
pub fn exchange_bytes(f: Vec<u8>) -> Vec<u8> {
    get_ch!().exchange_bytes(f)
}

/// Are you the first party in the MPC?
pub fn am_first() -> bool {
    get_ch!().base.talk_first
}

pub type Triple<F, G, H> = (MpcVal<F>, MpcVal<G>, MpcVal<H>);

/// Get a field triple
#[allow(dead_code)]
pub fn field_triple<F: Field>() -> Triple<F, F, F> {
    get_ch!().field_triple()
}

/// Copute a field product over SS data
pub fn field_mul<F: Field>(a: MpcVal<F>, b: MpcVal<F>) -> MpcVal<F> {
    get_ch!().field_mul(a, b)
}

/// Copute a field inverse over SS data
pub fn field_inv<F: Field>(a: MpcVal<F>) -> MpcVal<F> {
    get_ch!().field_inv(a)
}

/// Compute field inverses over SS data
pub fn field_batch_inv<F: Field>(a: Vec<MpcVal<F>>) -> Vec<MpcVal<F>> {
    get_ch!().field_batch_inv(a)
}

/// Compute field partial products over SS data
pub fn field_partial_products<F: Field>(a: Vec<MpcVal<F>>) -> Vec<MpcVal<F>> {
    get_ch!().field_partial_products(a)
}

/// Compute a field inverse over SS data
pub fn field_div<F: Field>(a: MpcVal<F>, b: MpcVal<F>) -> MpcVal<F> {
    let ch = &mut *get_ch!();
    let b_inv = ch.field_inv(b);
    ch.field_mul(a, b_inv)
}
/// Compute field divisions over SS data
pub fn field_batch_div<F: Field>(a: Vec<MpcVal<F>>, b: Vec<MpcVal<F>>) -> Vec<MpcVal<F>> {
    let ch = &mut *get_ch!();
    let b_inv = ch.field_batch_inv(b);
    ch.field_batch_mul(a, b_inv)
}

/// Copute a field product over SS data
pub fn field_batch_mul<F: Field>(a: Vec<MpcVal<F>>, b: Vec<MpcVal<F>>) -> Vec<MpcVal<F>> {
    get_ch!().field_batch_mul(a, b)
}

/// Copute a field-curve product over SS data
pub fn curve_mul<G: ProjectiveCurve>(a: MpcVal<G>, b: MpcVal<G::ScalarField>) -> MpcVal<G> {
    get_ch!().curve_mul(a, b)
}

/// Copute a pairing over SS data
pub fn pairing<E: PairingEngine>(
    a: MpcVal<E::G1Projective>,
    b: MpcVal<E::G2Projective>,
) -> MpcVal<E::Fqk> {
    get_ch!().pairing::<E>(a, b)
}

//impl<F: Field, C: AffineCurve<ScalarField=F>> Triple<F, C> for C {
//    fn triple() -> (MpcVal<Self>, MpcVal<F>, MpcVal<F>) {
//        //TODO: fix
//        (
//            MpcVal::from_shared(F::from(0u8)),
//            C::zero(),
//            MpcVal::from_shared(F::from(0u8)),
//        )
//    }
//}

pub fn deinit() {
    CH.lock().expect("Poisoned FieldChannel").base.stream = None;
}

pub use mpc_net::ChannelStats;

pub fn stats() -> ChannelStats {
    CH.lock().expect("Poisoned FieldChannel").base.stats()
}

pub fn reset_stats() {
    CH.lock().expect("Poisoned FieldChannel").base.reset_stats()
}

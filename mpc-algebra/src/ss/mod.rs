pub mod group;
pub mod share;
pub use share::*;
pub mod wire;
pub use wire::*;
pub mod com;

pub mod honest_but_curious {
    use ark_ec::PairingEngine;
    use crate::pairing::RevealPairingEngine;
    use super::{
        wire::{
            field,
            group,
            pairing,
        },
        share::add::*,
    };
    pub type MpcField<F> = field::MpcField<F, AdditiveScalarShare<F>>;
    pub type MpcGroup<G> = group::MpcGroup<G, AdditiveGroupShare<G, NaiveMsm<G>>>;
    pub type MpcG1Affine<E> = pairing::MpcG1Affine<E, AdditivePairingShare<E>>;
    pub type MpcG2Affine<E> = pairing::MpcG2Affine<E, AdditivePairingShare<E>>;
    pub type MpcG1Projective<E> = pairing::MpcG1Projective<E, AdditivePairingShare<E>>;
    pub type MpcG2Projective<E> = pairing::MpcG2Projective<E, AdditivePairingShare<E>>;
    pub type MpcG1Prep<E> = pairing::MpcG1Prep<E, AdditivePairingShare<E>>;
    pub type MpcG2Prep<E> = pairing::MpcG2Prep<E, AdditivePairingShare<E>>;
    pub type MpcPairingEngine<E> = pairing::MpcPairingEngine<E, AdditivePairingShare<E>>;

    impl<E: PairingEngine> RevealPairingEngine<E> for MpcPairingEngine<E> {
    }
}

pub mod malicious_majority {
    use ark_ec::PairingEngine;
    use crate::pairing::RevealPairingEngine;
    use super::{
        wire::{
            field,
            group,
            pairing,
        },
        share::spdz::*,
        share::add::NaiveMsm,
    };
    pub type MpcField<F> = field::MpcField<F, SpdzScalarShare<F>>;
    pub type MpcGroup<G> = group::MpcGroup<G, SpdzGroupShare<G, NaiveMsm<G>>>;
    pub type MpcG1Affine<E> = pairing::MpcG1Affine<E, SpdzPairingShare<E>>;
    pub type MpcG2Affine<E> = pairing::MpcG2Affine<E, SpdzPairingShare<E>>;
    pub type MpcG1Projective<E> = pairing::MpcG1Projective<E, SpdzPairingShare<E>>;
    pub type MpcG2Projective<E> = pairing::MpcG2Projective<E, SpdzPairingShare<E>>;
    pub type MpcG1Prep<E> = pairing::MpcG1Prep<E, SpdzPairingShare<E>>;
    pub type MpcG2Prep<E> = pairing::MpcG2Prep<E, SpdzPairingShare<E>>;
    pub type MpcPairingEngine<E> = pairing::MpcPairingEngine<E, SpdzPairingShare<E>>;

    impl<E: PairingEngine> RevealPairingEngine<E> for MpcPairingEngine<E> {
    }
}

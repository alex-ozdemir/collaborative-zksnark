#![macro_use]
#![feature(associated_type_defaults)]

pub mod reveal;
pub use reveal::*;
pub mod channel;
pub mod com;
pub mod group;
pub mod share;
pub use share::*;
pub mod wire;
pub use wire::*;

pub mod honest_but_curious {
    use super::{
        share::add::*,
        share::msm::NaiveMsm,
        wire::{field, group, pairing},
    };
    pub type MpcField<F> = field::MpcField<F, AdditiveFieldShare<F>>;
    pub type MpcGroup<G> = group::MpcGroup<G, AdditiveGroupShare<G, NaiveMsm<G>>>;
    pub type MpcG1Affine<E> = pairing::MpcG1Affine<E, AdditivePairingShare<E>>;
    pub type MpcG2Affine<E> = pairing::MpcG2Affine<E, AdditivePairingShare<E>>;
    pub type MpcG1Projective<E> = pairing::MpcG1Projective<E, AdditivePairingShare<E>>;
    pub type MpcG2Projective<E> = pairing::MpcG2Projective<E, AdditivePairingShare<E>>;
    pub type MpcG1Prep<E> = pairing::MpcG1Prep<E, AdditivePairingShare<E>>;
    pub type MpcG2Prep<E> = pairing::MpcG2Prep<E, AdditivePairingShare<E>>;
    pub type MpcPairingEngine<E> = pairing::MpcPairingEngine<E, AdditivePairingShare<E>>;
}

pub mod malicious_majority {
    use super::{
        share::msm::NaiveMsm,
        share::spdz::*,
        wire::{field, group, pairing},
    };
    pub type MpcField<F> = field::MpcField<F, SpdzFieldShare<F>>;
    pub type MpcGroup<G> = group::MpcGroup<G, SpdzGroupShare<G, NaiveMsm<G>>>;
    pub type MpcG1Affine<E> = pairing::MpcG1Affine<E, SpdzPairingShare<E>>;
    pub type MpcG2Affine<E> = pairing::MpcG2Affine<E, SpdzPairingShare<E>>;
    pub type MpcG1Projective<E> = pairing::MpcG1Projective<E, SpdzPairingShare<E>>;
    pub type MpcG2Projective<E> = pairing::MpcG2Projective<E, SpdzPairingShare<E>>;
    pub type MpcG1Prep<E> = pairing::MpcG1Prep<E, SpdzPairingShare<E>>;
    pub type MpcG2Prep<E> = pairing::MpcG2Prep<E, SpdzPairingShare<E>>;
    pub type MpcPairingEngine<E> = pairing::MpcPairingEngine<E, SpdzPairingShare<E>>;
}

pub mod honest_majority {
    use super::{
        share::msm::NaiveMsm,
        share::gsz20::{field::GszFieldShare, group::GszGroupShare},
        wire::{field, group},
    };
    pub type MpcField<F> = field::MpcField<F, GszFieldShare<F>>;
    pub type MpcGroup<G> = group::MpcGroup<G, GszGroupShare<G, NaiveMsm<G>>>;
    // pub type MpcG1Affine<E> = pairing::MpcG1Affine<E, GszPairingShare<E>>;
    // pub type MpcG2Affine<E> = pairing::MpcG2Affine<E, GszPairingShare<E>>;
    // pub type MpcG1Projective<E> = pairing::MpcG1Projective<E, GszPairingShare<E>>;
    // pub type MpcG2Projective<E> = pairing::MpcG2Projective<E, GszPairingShare<E>>;
    // pub type MpcG1Prep<E> = pairing::MpcG1Prep<E, GszPairingShare<E>>;
    // pub type MpcG2Prep<E> = pairing::MpcG2Prep<E, GszPairingShare<E>>;
    // pub type MpcPairingEngine<E> = pairing::MpcPairingEngine<E, GszPairingShare<E>>;
}

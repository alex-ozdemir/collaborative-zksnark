use crate::Reveal;
use ark_ec::PairingEngine;

pub trait RevealPairingEngine<E>: PairingEngine
where
    E: PairingEngine,
    <Self as PairingEngine>::Fr: Reveal<Base = E::Fr>,
    <Self as PairingEngine>::G1Affine: Reveal<Base = E::G1Affine>,
    <Self as PairingEngine>::G2Affine: Reveal<Base = E::G2Affine>,
    <Self as PairingEngine>::G1Projective: Reveal<Base = E::G1Projective>,
    <Self as PairingEngine>::G2Projective: Reveal<Base = E::G2Projective>,
    <Self as PairingEngine>::Fqk: Reveal<Base = E::Fqk>,
{
    type PubFr = E::Fr;
    type PubG1Affine = E::G1Affine;
    type PubG2Affine = E::G2Affine;
    type PubG1Projective = E::G1Projective;
    type PubG2Projective = E::G2Projective;
    type PubFqk = E::Fqk;
}

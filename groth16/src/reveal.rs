#![allow(missing_docs)]
use ark_ec::PairingEngine;
use mpc_algebra::*;

use super::*;

impl<E: PairingEngine, S: PairingShare<E>> Reveal
    for Proof<MpcPairingEngine<E, S>>
{
    type Base = Proof<E>;
    struct_reveal_simp_impl!(Proof; a, b, c);
}

impl<E: PairingEngine, S: PairingShare<E>> Reveal
    for VerifyingKey<MpcPairingEngine<E, S>>
{
    type Base = VerifyingKey<E>;
    struct_reveal_simp_impl!(VerifyingKey;
    alpha_g1,
    beta_g2,
    gamma_g2,
    delta_g2,
    gamma_abc_g1);
}

impl<E: PairingEngine, S: PairingShare<E>> Reveal
    for PreparedVerifyingKey<MpcPairingEngine<E, S>>
{
    type Base = PreparedVerifyingKey<E>;
    struct_reveal_simp_impl!(PreparedVerifyingKey;
    vk,
    alpha_g1_beta_g2,
    gamma_g2_neg_pc,
    delta_g2_neg_pc);
}

impl<E: PairingEngine, S: PairingShare<E>> Reveal
    for ProvingKey<MpcPairingEngine<E, S>>
{
    type Base = ProvingKey<E>;
    struct_reveal_simp_impl!(ProvingKey;
    vk,
    beta_g1,
    delta_g1,
    a_query,
    b_g1_query,
    b_g2_query,
    h_query,
    l_query);
}

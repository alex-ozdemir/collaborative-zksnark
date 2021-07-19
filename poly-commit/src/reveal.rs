#![allow(missing_docs)]
use ark_ec::PairingEngine;
use ark_ff::{Field, PrimeField};
use ark_poly::univariate::DensePolynomial;
use mpc_trait::{struct_mpc_wire_simp_impl, MpcWire};
use mpc_algebra::*;

use std::rc::Rc;

use crate::{kzg10, marlin_pc, BatchLCProof, LabeledCommitment, LabeledPolynomial, PCCommitment};
use marlin_pc::*;

impl<E: PairingEngine, S: PairingShare<E>> Reveal for Commitment<MpcPairingEngine<E, S>> {
    type Base = Commitment<E>;
    struct_reveal_simp_impl!(Commitment; comm, shifted_comm);
}

impl<E: PrimeField, S: FieldShare<E>> Reveal
    for kzg10::Randomness<MpcField<E, S>, DensePolynomial<MpcField<E, S>>>
{
    type Base = kzg10::Randomness<E, DensePolynomial<E>>;
    struct_reveal_simp_impl!(kzg10::Randomness; blinding_polynomial, _field);
}

impl<E: PrimeField, S: FieldShare<E>> Reveal
    for Randomness<MpcField<E, S>, DensePolynomial<MpcField<E, S>>>
{
    type Base = Randomness<E, DensePolynomial<E>>;
    struct_reveal_simp_impl!(Randomness; rand, shifted_rand);
}

impl<E: PairingEngine, S: PairingShare<E>> Reveal for kzg10::Commitment<MpcPairingEngine<E, S>> {
    type Base = kzg10::Commitment<E>;

    fn reveal(self) -> Self::Base {
        kzg10::Commitment(self.0.reveal())
    }

    fn from_add_shared(b: Self::Base) -> Self {
        kzg10::Commitment(<MpcPairingEngine<E, S> as PairingEngine>::G1Affine::from_add_shared(b.0))
    }

    fn from_public(b: Self::Base) -> Self {
        kzg10::Commitment(<MpcPairingEngine<E, S> as PairingEngine>::G1Affine::from_public(b.0))
    }
}

impl<E: PairingEngine, S: PairingShare<E>> Reveal for kzg10::Proof<MpcPairingEngine<E, S>> {
    type Base = kzg10::Proof<E>;
    struct_reveal_simp_impl!(kzg10::Proof; w, random_v);
}
impl<E: PairingEngine, S: PairingShare<E>> Reveal
    for kzg10::UniversalParams<MpcPairingEngine<E, S>>
{
    type Base = kzg10::UniversalParams<E>;
    struct_reveal_simp_impl!(kzg10::UniversalParams;
    powers_of_g,
    powers_of_gamma_g,
    h,
    beta_h,
    neg_powers_of_h,
    prepared_h,
    prepared_beta_h);
}

impl<E: PairingEngine, S: PairingShare<E>> Reveal for kzg10::VerifierKey<MpcPairingEngine<E, S>> {
    type Base = kzg10::VerifierKey<E>;
    struct_reveal_simp_impl!(kzg10::VerifierKey;
    g,
    gamma_g,
    h,
    beta_h,
    prepared_h,
    prepared_beta_h
    );
}
impl<E: PairingEngine, S: PairingShare<E>> Reveal for VerifierKey<MpcPairingEngine<E, S>> {
    type Base = VerifierKey<E>;
    struct_reveal_simp_impl!(VerifierKey;
         vk,
         degree_bounds_and_shift_powers,
         max_degree,
         supported_degree);
}
impl<E: PairingEngine, S: PairingShare<E>> Reveal
    for BatchLCProof<
        <MpcPairingEngine<E, S> as PairingEngine>::Fr,
        DensePolynomial<<MpcPairingEngine<E, S> as PairingEngine>::Fr>,
        MarlinKZG10<
            MpcPairingEngine<E, S>,
            DensePolynomial<<MpcPairingEngine<E, S> as PairingEngine>::Fr>,
        >,
    >
{
    type Base = BatchLCProof<
        <E as PairingEngine>::Fr,
        DensePolynomial<<E as PairingEngine>::Fr>,
        MarlinKZG10<E, DensePolynomial<<E as PairingEngine>::Fr>>,
    >;
    struct_reveal_simp_impl!(BatchLCProof; proof, evals);
}

impl<E: PairingEngine, S: PairingShare<E>> Reveal for CommitterKey<MpcPairingEngine<E, S>> {
    type Base = CommitterKey<E>;
    struct_reveal_simp_impl!(CommitterKey; powers, shifted_powers, powers_of_gamma_g, enforced_degree_bounds, max_degree);
}

impl<C: PCCommitment + Reveal> Reveal for LabeledCommitment<C>
where
    C::Base: PCCommitment,
{
    type Base = LabeledCommitment<C::Base>;
    fn reveal(self) -> Self::Base {
        LabeledCommitment::new(
            self.label().clone(),
            self.commitment.clone().reveal(),
            self.degree_bound(),
        )
    }

    fn from_add_shared(b: Self::Base) -> Self {
        LabeledCommitment::new(
            b.label().clone(),
            Reveal::from_add_shared(b.commitment.clone()),
            b.degree_bound(),
        )
    }

    fn from_public(b: Self::Base) -> Self {
        LabeledCommitment::new(
            b.label().clone(),
            Reveal::from_public(b.commitment.clone()),
            b.degree_bound(),
        )
    }
}

impl<F: PrimeField, S: FieldShare<F>> Reveal
    for LabeledPolynomial<MpcField<F, S>, DensePolynomial<MpcField<F, S>>>
{
    type Base = LabeledPolynomial<F, DensePolynomial<F>>;
    fn reveal(self) -> Self::Base {
        LabeledPolynomial::new(
            self.label().clone(),
            self.polynomial().clone().reveal(),
            self.degree_bound(),
            self.hiding_bound(),
        )
    }

    fn from_add_shared(b: Self::Base) -> Self {
        LabeledPolynomial::new(
            b.label().clone(),
            Reveal::from_add_shared(b.polynomial().clone()),
            b.degree_bound(),
            b.hiding_bound(),
        )
    }

    fn from_public(b: Self::Base) -> Self {
        LabeledPolynomial::new(
            b.label().clone(),
            Reveal::from_public(b.polynomial().clone()),
            b.degree_bound(),
            b.hiding_bound(),
        )
    }
}

impl<E: Field> MpcWire for LabeledPolynomial<E, DensePolynomial<E>> {
    fn publicize(&mut self) {
        let mut p = (*self.polynomial).clone();
        p.publicize();
        self.polynomial = Rc::new(p);
    }
    fn is_shared(&self) -> bool {
        self.polynomial.is_shared()
    }
}

impl<C: PCCommitment + MpcWire> MpcWire for LabeledCommitment<C> {
    struct_mpc_wire_simp_impl!(LabeledCommitment; commitment);
}

impl<C: PairingEngine> MpcWire for Commitment<C> {
    struct_mpc_wire_simp_impl!(Commitment; comm, shifted_comm);
}

impl<C: PairingEngine> MpcWire for kzg10::Commitment<C> {
    struct_mpc_wire_simp_impl!(kzg10::Commitment; 0);
}

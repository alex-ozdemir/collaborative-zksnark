use super::*;

use ark_poly_commit::marlin_pc::MarlinKZG10;
use ark_poly_commit::{Evaluations, BatchLCProof, PolynomialCommitment, QuerySet, LabeledPolynomial, LabeledCommitment, LinearCombination, PCRandomness};

use std::marker::PhantomData;


pub struct MpcPolyCommit<F: Field, P: Polynomial<F>, PC: PolynomialCommitment<F, P>>(pub PC, pub PhantomData<F>, pub PhantomData<P>);


type F = ark_bls12_377::Fr;
type P = ark_poly::univariate::DensePolynomial<F>;
type MP = ark_poly::univariate::DensePolynomial<MpcVal<F>>;
type E = ark_bls12_377::Bls12_377;
type ME = crate::mpc::MpcPairingEngine<E>;
type PC = MarlinKZG10<E, P>;
type PCR = <PC as PolynomialCommitment<F, P>>::Randomness;
type MPC = MarlinKZG10<ME, MP>;
type MPCR = <MPC as PolynomialCommitment<MpcVal<F>, MP>>::Randomness;

impl PCRandomness for MpcVal<PCR> {
    fn empty() -> Self {
        MpcVal::from_public(PCR::empty())
    }
    fn rand<R: rand::RngCore>(
        num_queries: usize,
        has_degree_bound: bool,
        num_vars: Option<usize>,
        rng: &mut R
    ) -> Self {
        MpcVal::from_shared(PCR::rand(num_queries, has_degree_bound, num_vars, rng))
    }
}

// Lift a locally computed commitent key to an MPC one.
pub fn lift_ck(ck: ark_poly_commit::marlin_pc::CommitterKey<E>) -> ark_poly_commit::marlin_pc::CommitterKey<ME> {
    ark_poly_commit::marlin_pc::CommitterKey {
        powers: ck.powers.into_iter().map(MpcCurve::from_public).collect(),
        shifted_powers: ck.shifted_powers.map(|v| v.into_iter().map(MpcCurve::from_public).collect()),
        powers_of_gamma_g: ck.powers_of_gamma_g.into_iter().map(MpcCurve::from_public).collect(),
        enforced_degree_bounds: ck.enforced_degree_bounds,
        max_degree: ck.max_degree,
    }
}


// Lower a (batched) proof
pub fn lower_batch_pf(pf: BatchLCProof<MpcVal<F>, MP, MpcMarlinKZG10>) -> BatchLCProof<F, P, PC> {
    BatchLCProof {
        proof: pf.proof,
        evals: pf.evals.map(|es| es.into_iter().map(MpcVal::publicize_unwrap).collect()),
    }
}

// Lower an mpc-copmuted proof to a local one (by publicizing).
fn lower_pf(pf: ark_poly_commit::kzg10::Proof<ME>) -> ark_poly_commit::kzg10::Proof<E> {
    ark_poly_commit::kzg10::Proof {
        w: pf.w.publicize_unwrap(),
        random_v: pf.random_v.map(MpcVal::publicize_unwrap),
    }
}

// Lower an mpc-computed commitment to a local one (by publicizing).
fn lower_commitment(c: ark_poly_commit::marlin_pc::Commitment<ME>) -> ark_poly_commit::marlin_pc::Commitment<E> {
    ark_poly_commit::marlin_pc::Commitment {
        comm: lower_kzg_commitment(c.comm),
        shifted_comm: c.shifted_comm.map(lower_kzg_commitment),
    }
}

// Lower an mpc-computed KZG commitment to a local one (by publicizing).
fn lower_kzg_commitment(c: ark_poly_commit::kzg10::Commitment<ME>) -> ark_poly_commit::kzg10::Commitment<E> {
    ark_poly_commit::kzg10::Commitment(
        c.0.publicize_unwrap(),
    )
}

// Lower an mpc-computed KZG commitment to a local one (by publicizing).
fn lift_kzg_commitment(c: ark_poly_commit::kzg10::Commitment<E>) -> ark_poly_commit::kzg10::Commitment<ME> {
    ark_poly_commit::kzg10::Commitment(
        MpcCurve::from_public(c.0)
    )
}

// Lower an mpc-computed KZG commitment to a local one (by publicizing).
pub fn lift_commitment(c: ark_poly_commit::marlin_pc::Commitment<E>) -> ark_poly_commit::marlin_pc::Commitment<ME> {
    ark_poly_commit::marlin_pc::Commitment {
        comm: lift_kzg_commitment(c.comm),
        shifted_comm: c.shifted_comm.map(lift_kzg_commitment),
    }
}

// Lower an mpc-computed labelled commitment to a local one (by publicizing).
pub fn lift_labeled_commitment(c: LabeledCommitment<ark_poly_commit::marlin_pc::Commitment<E>>) -> LabeledCommitment<ark_poly_commit::marlin_pc::Commitment<ME>> {
    LabeledCommitment::new(c.label().clone(), lift_commitment(c.commitment().clone()), c.degree_bound())
}

// Lower an mpc-computed labelled commitment to a local one (by publicizing).
fn lower_labeled_commitment(c: LabeledCommitment<ark_poly_commit::marlin_pc::Commitment<ME>>) -> LabeledCommitment<ark_poly_commit::marlin_pc::Commitment<E>> {
    LabeledCommitment::new(c.label().clone(), lower_commitment(c.commitment().clone()), c.degree_bound())
}

pub fn lift_randomness(r: PCR) -> MPCR {
    ark_poly_commit::marlin_pc::Randomness {
        rand: lift_kzg_randomness(r.rand),
        shifted_rand: r.shifted_rand.map(lift_kzg_randomness),
    }
}

fn lift_kzg_randomness(r: ark_poly_commit::kzg10::Randomness<F, P>) -> ark_poly_commit::kzg10::Randomness<MpcVal<F>, MP> {
    ark_poly_commit::kzg10::Randomness {
        blinding_polynomial: MP::from_coefficients_vec(r.blinding_polynomial.coeffs().iter().cloned().map(MpcVal::from_public).collect()),
        _field: std::marker::PhantomData::default(),
    }
}

impl PolynomialCommitment<MpcVal<F>, MP> for MpcPolyCommit<F, P, PC>
where
    for<'a, 'b> &'a P: Div<&'b P, Output = P>,
{
    type UniversalParams = <PC as PolynomialCommitment<F, P>>::UniversalParams;
    type CommitterKey = <PC as PolynomialCommitment<F, P>>::CommitterKey;
    type VerifierKey = <PC as PolynomialCommitment<F, P>>::VerifierKey;
    type PreparedVerifierKey = <PC as PolynomialCommitment<F, P>>::PreparedVerifierKey;
    type Commitment = <PC as PolynomialCommitment<F, P>>::Commitment;
    type PreparedCommitment = <PC as PolynomialCommitment<F, P>>::PreparedCommitment;
    type Randomness = <MPC as PolynomialCommitment<MpcVal<F>, MP>>::Randomness;
    type Proof = <PC as PolynomialCommitment<F, P>>::Proof;
    type BatchProof = Vec<Self::Proof>;
    type Error = <PC as PolynomialCommitment<F, P>>::Error;

    /// Constructs public parameters when given as input the maximum degree `max_degree`
    /// for the polynomial commitment scheme.
    fn setup<R: RngCore>(
        max_degree: usize,
        num_vars: Option<usize>,
        rng: &mut R,
    ) -> Result<Self::UniversalParams, Self::Error> {
        PC::setup(max_degree, num_vars, rng)
    }

    fn trim(
        pp: &Self::UniversalParams,
        supported_degree: usize,
        supported_hiding_bound: usize,
        enforced_degree_bounds: Option<&[usize]>,
    ) -> Result<(Self::CommitterKey, Self::VerifierKey), Self::Error> {
        PC::trim(pp, supported_degree, supported_hiding_bound, enforced_degree_bounds)
    }

    /// Outputs a commitment to `polynomial`.
    fn commit<'a>(
        ck: &Self::CommitterKey,
        polynomials: impl IntoIterator<Item = &'a LabeledPolynomial<MpcVal<F>, MP>>,
        rng: Option<&mut dyn RngCore>,
    ) -> Result<
        (
            Vec<LabeledCommitment<Self::Commitment>>,
            Vec<Self::Randomness>,
        ),
        Self::Error,
    >
    where
        P: 'a,
    {
        let lifted_ck = lift_ck(ck.clone());
        let (commitments, randomness) = MPC::commit(&lifted_ck, polynomials, rng)?;
        Ok((commitments.into_iter().map(lower_labeled_commitment).collect(), randomness))
    }

    /// On input a polynomial `p` and a point `point`, outputs a proof for the same.
    fn open_individual_opening_challenges<'a>(
        ck: &Self::CommitterKey,
        labeled_polynomials: impl IntoIterator<Item = &'a LabeledPolynomial<MpcVal<F>, MP>>,
        _commitments: impl IntoIterator<Item = &'a LabeledCommitment<Self::Commitment>>,
        point: &'a MpcVal<F>,
        opening_challenges: &dyn Fn(u64) -> MpcVal<F>,
        rands: impl IntoIterator<Item = &'a Self::Randomness>,
        rng: Option<&mut dyn RngCore>,
    ) -> Result<Self::Proof, Self::Error>
    where
        P: 'a,
        Self::Randomness: 'a,
        Self::Commitment: 'a,
    {
        let lifted_ck = lift_ck(ck.clone());
        MPC::open_individual_opening_challenges(&lifted_ck, labeled_polynomials, &[], point, opening_challenges, rands, rng).map(lower_pf)
    }

    /// Verifies that `value` is the evaluation at `x` of the polynomial
    /// committed inside `comm`.
    fn check_individual_opening_challenges<'a>(
        vk: &Self::VerifierKey,
        commitments: impl IntoIterator<Item = &'a LabeledCommitment<Self::Commitment>>,
        point: &'a MpcVal<F>,
        values: impl IntoIterator<Item = MpcVal<F>>,
        proof: &Self::Proof,
        opening_challenges: &dyn Fn(u64) -> MpcVal<F>,
        rng: Option<&mut dyn RngCore>,
    ) -> Result<bool, Self::Error>
    where
        Self::Commitment: 'a,
    {
        println!("Check individual");
        assert!(!point.shared, "shared point");
        let opening_challenges_local = |u| {
            let c = opening_challenges(u);
            assert!(!c.shared, "shared challenge");
            c.val
        };
        let values: Vec<F> = values.into_iter().map(|v| {
            assert!(!v.shared, "shared value");
            v.val
        }).collect();
        PC::check_individual_opening_challenges(vk, commitments, &point.val, values, proof, &opening_challenges_local, rng)
    }

    fn batch_check_individual_opening_challenges<'a, R: RngCore>(
        vk: &Self::VerifierKey,
        commitments: impl IntoIterator<Item = &'a LabeledCommitment<Self::Commitment>>,
        query_set: &QuerySet<MpcVal<F>>,
        values: &Evaluations<MpcVal<F>, MpcVal<F>>,
        proof: &Self::BatchProof,
        opening_challenges: &dyn Fn(u64) -> MpcVal<F>,
        rng: &mut R,
    ) -> Result<bool, Self::Error>
    where
        Self::Commitment: 'a,
    {
        let opening_challenges_local = |u| {
            let c = opening_challenges(u);
            assert!(!c.shared, "shared challenge");
            c.val
        };
        let values: Evaluations<F, F> = values.into_iter().map(|((label, input), output)| {
            assert!(!input.shared, "shared eval input");
            assert!(!output.shared, "shared eval output");
            ((label.clone(), input.val), output.val)
        }).collect();
        let query_set: QuerySet<F> = query_set.into_iter().map(|(poly_label, (pt_label, pt))| {
            assert!(!pt.shared, "shared eval pt");
            (poly_label.clone(), (pt_label.clone(), pt.val))
        }).collect();
        PC::batch_check_individual_opening_challenges(vk, commitments, &query_set, &values, proof, &opening_challenges_local, rng)
    }

    fn open_combinations_individual_opening_challenges<'a>(
        ck: &Self::CommitterKey,
        lc_s: impl IntoIterator<Item = &'a LinearCombination<MpcVal<F>>>,
        polynomials: impl IntoIterator<Item = &'a LabeledPolynomial<MpcVal<F>, MP>>,
        commitments: impl IntoIterator<Item = &'a LabeledCommitment<Self::Commitment>>,
        query_set: &QuerySet<MpcVal<F>>,
        opening_challenges: &dyn Fn(u64) -> MpcVal<F>,
        rands: impl IntoIterator<Item = &'a Self::Randomness>,
        rng: Option<&mut dyn RngCore>,
    ) -> Result<BatchLCProof<MpcVal<F>, MP, Self>, Self::Error>
    where
        P: 'a,
        Self::Randomness: 'a,
        Self::Commitment: 'a,
    {
        let lifted_ck = lift_ck(ck.clone());
        let lifted_commits: Vec<LabeledCommitment<<MPC as PolynomialCommitment<MpcVal<F>, MP>>::Commitment>> = commitments.into_iter().cloned().map(lift_labeled_commitment).collect();
        // TODO: revisit these copies, which seems necessary b/c of some impl trait/lifetime
        // interaction: https://stackoverflow.com/questions/67204021
        let lc_s = lc_s.into_iter().cloned().collect::<Vec<_>>();
        let polynomials = polynomials.into_iter().cloned().collect::<Vec<_>>();
        let rands = rands.into_iter().cloned().collect::<Vec<_>>();

        let r: BatchLCProof<MpcVal<F>, MP, MPC> = MPC::open_combinations_individual_opening_challenges(&lifted_ck, &lc_s, &polynomials, &lifted_commits, query_set, opening_challenges, &rands, rng)?;
        Ok(BatchLCProof {
            proof: r.proof.into_iter().map(lower_pf).collect(),
            evals: r.evals,
        })
    }

    /// Checks that `values` are the true evaluations at `query_set` of the polynomials
    /// committed in `labeled_commitments`.
    fn check_combinations_individual_opening_challenges<'a, R: RngCore>(
        _vk: &Self::VerifierKey,
        _lc_s: impl IntoIterator<Item = &'a LinearCombination<MpcVal<F>>>,
        _commitments: impl IntoIterator<Item = &'a LabeledCommitment<Self::Commitment>>,
        _query_set: &QuerySet<MpcVal<F>>,
        _evaluations: &Evaluations<MpcVal<F>, MpcVal<F>>,
        _proof: &BatchLCProof<MpcVal<F>, MP, Self>,
        _opening_challenges: &dyn Fn(u64) -> MpcVal<F>,
        _rng: &mut R,
    ) -> Result<bool, Self::Error>
    where
        Self::Commitment: 'a,
    {
        unimplemented!()
    }

    /// On input a list of labeled polynomials and a query set, `open` outputs a proof of evaluation
    /// of the polynomials at the points in the query set.
    fn batch_open_individual_opening_challenges<'a>(
        _ck: &Self::CommitterKey,
        _labeled_polynomials: impl IntoIterator<Item = &'a LabeledPolynomial<MpcVal<F>, MP>>,
        _commitments: impl IntoIterator<Item = &'a LabeledCommitment<Self::Commitment>>,
        _query_set: &QuerySet<MpcVal<F>>,
        _opening_challenges: &dyn Fn(u64) -> MpcVal<F>,
        _rands: impl IntoIterator<Item = &'a Self::Randomness>,
        _rng: Option<&mut dyn RngCore>,
    ) -> Result<Vec<Self::Proof>, Self::Error>
    where
        P: 'a,
        Self::Randomness: 'a,
        Self::Commitment: 'a,
    {
        unimplemented!()
    }
}

/// Marlin PC run over MPC types
pub type MpcMarlinKZG10 = MpcPolyCommit<F, P, PC>;

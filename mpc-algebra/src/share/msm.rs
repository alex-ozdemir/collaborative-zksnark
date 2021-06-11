
/// Multi-scalar multiplications
pub trait Msm<G, S>: Send + Sync + 'static {
    fn msm(bases: &[G], scalars: &[S]) -> G;
}


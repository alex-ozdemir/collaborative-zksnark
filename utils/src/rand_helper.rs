use rand::{
    distributions::{Distribution, Standard},
    rngs::StdRng,
    Rng,
};

pub use rand;
pub use rand_xorshift::XorShiftRng;
use mpc_trait::MpcWire;

pub trait UniformRand: Sized {
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self;
}

pub trait PubUniformRand: Sized + MpcWire + UniformRand {
    fn pub_rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        <Self as UniformRand>::rand(rng)
    }
}

impl<T> UniformRand for T
where
    Standard: Distribution<T>,
{
    #[inline]
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        rng.sample(Standard)
    }
}

/// Should be used only for tests, not for any real world usage.
pub fn test_rng() -> StdRng {
    use rand::SeedableRng;
    // arbitrary seed
    let seed = [
        1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];
    rand::rngs::StdRng::from_seed(seed)
}

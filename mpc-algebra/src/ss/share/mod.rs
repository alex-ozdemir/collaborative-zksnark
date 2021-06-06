
pub mod field;
pub use field::*;
pub mod group;
pub use group::*;
pub mod pairing;
pub use pairing::*;
pub mod msm;
pub mod add;
pub use add::*;
pub mod spdz;
pub use spdz::*;

pub trait BeaverSource<A, B, C>: Clone {
    fn triple(&mut self) -> (A, B, C);
    fn triples(&mut self, n: usize) -> (Vec<A>, Vec<B>, Vec<C>) {
        let mut xs = Vec::new();
        let mut ys = Vec::new();
        let mut zs = Vec::new();
        for _ in 0..n {
            let (x, y, z) = self.triple();
            xs.push(x);
            ys.push(y);
            zs.push(z);
        }
        (xs, ys, zs)
    }
    fn inv_pair(&mut self) -> (B, B);
    fn inv_pairs(&mut self, n: usize) -> (Vec<B>, Vec<B>) {
        let mut xs = Vec::new();
        let mut ys = Vec::new();
        for _ in 0..n {
            let (x, y) = self.inv_pair();
            xs.push(x);
            ys.push(y);
        }
        (xs, ys)
    }
}


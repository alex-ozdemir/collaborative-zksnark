#![macro_use]
use ark_std::{collections::BTreeMap, marker::PhantomData, rc::Rc};
use rand::Rng;

/// A type should implement [Reveal] if it represents the MPC abstraction of some base type.
///
/// It is typically implemented for shared (or possibly shared) data.
///
/// For example, and additive secret share can be viewed as the MPC abstraction of the underlying
/// type.
///
/// Typically a [Reveal] implementation assumes that there are a collection of other machines which
/// are participating in a protocol with this one, and that all are running the same code (but with
/// different data!).
pub trait Reveal: Sized {
    type Base;

    /// Reveal shared data, yielding plain data.
    fn reveal(self) -> Self::Base;
    /// Construct a share of the sum of the `b` over all machines in the protocol.
    fn from_add_shared(b: Self::Base) -> Self;
    /// Lift public data (same in all machines) into shared data.
    fn from_public(b: Self::Base) -> Self;
    /// If this share type has some underlying value of the base type, grabs it.
    ///
    /// The semantics of this are highly dependent on the sharing system.
    fn unwrap_as_public(self) -> Self::Base {
        unimplemented!("No unwrap as public for {}", std::any::type_name::<Self>())
    }
    /// Have the king share their `b` value, and send shares to all parties.
    fn king_share<R: Rng>(_b: Self::Base, _rng: &mut R) -> Self {
        unimplemented!("No king share for {}", std::any::type_name::<Self>())
    }
    /// Have the king share their `b` values, and send shares to all parties.
    fn king_share_batch<R: Rng>(bs: Vec<Self::Base>, rng: &mut R) -> Vec<Self> {
        bs.into_iter().map(|b| Self::king_share(b, rng)).collect()
    }
    /// Initialize the network protocol associated with this sharing system, if it is not
    /// initialized.
    fn init_protocol() {}
    /// Destroy the network protocol associated with this sharing system, if it is initalized.
    fn deinit_protocol() {}
}

impl Reveal for usize {
    type Base = usize;

    fn reveal(self) -> Self::Base {
        self
    }

    fn from_add_shared(b: Self::Base) -> Self {
        b
    }

    fn from_public(b: Self::Base) -> Self {
        b
    }

    fn unwrap_as_public(self) -> Self::Base {
        self
    }

    fn king_share<R: Rng>(b: Self::Base, _rng: &mut R) -> Self {
        b
    }
}

impl<T: Reveal> Reveal for PhantomData<T> {
    type Base = PhantomData<T::Base>;

    fn reveal(self) -> Self::Base {
        PhantomData::default()
    }

    fn from_add_shared(_b: Self::Base) -> Self {
        PhantomData::default()
    }

    fn from_public(_b: Self::Base) -> Self {
        PhantomData::default()
    }
    fn unwrap_as_public(self) -> Self::Base {
        PhantomData::default()
    }
    fn king_share<R: Rng>(_b: Self::Base, _rng: &mut R) -> Self {
        PhantomData::default()
    }

    fn init_protocol() {
        T::init_protocol()
    }

    fn deinit_protocol() {
        T::deinit_protocol()
    }
}

impl<T: Reveal> Reveal for Vec<T> {
    type Base = Vec<T::Base>;
    fn reveal(self) -> Self::Base {
        self.into_iter().map(|x| x.reveal()).collect()
    }
    fn from_public(other: Self::Base) -> Self {
        other
            .into_iter()
            .map(|x| <T as Reveal>::from_public(x))
            .collect()
    }
    fn from_add_shared(other: Self::Base) -> Self {
        other
            .into_iter()
            .map(|x| <T as Reveal>::from_add_shared(x))
            .collect()
    }
    fn unwrap_as_public(self) -> Self::Base {
        self
            .into_iter()
            .map(|x| <T as Reveal>::unwrap_as_public(x))
            .collect()
    }
    fn king_share<R: Rng>(b: Self::Base, rng: &mut R) -> Self {
        T::king_share_batch(b, rng)
    }

    fn init_protocol() {
        T::init_protocol()
    }

    fn deinit_protocol() {
        T::deinit_protocol()
    }
}

impl<K: Reveal + Ord, V: Reveal> Reveal for BTreeMap<K, V>
where
    K::Base: Ord,
{
    type Base = BTreeMap<K::Base, V::Base>;
    fn reveal(self) -> Self::Base {
        self.into_iter().map(|x| x.reveal()).collect()
    }
    fn from_public(other: Self::Base) -> Self {
        other.into_iter().map(|x| Reveal::from_public(x)).collect()
    }
    fn from_add_shared(other: Self::Base) -> Self {
        other
            .into_iter()
            .map(|x| Reveal::from_add_shared(x))
            .collect()
    }
    fn unwrap_as_public(self) -> Self::Base {
        self
            .into_iter()
            .map(|x| Reveal::unwrap_as_public(x))
            .collect()
    }

    fn init_protocol() {
        K::init_protocol();
        V::init_protocol();
    }

    fn deinit_protocol() {
        K::deinit_protocol();
        V::deinit_protocol();
    }
}

impl<T: Reveal> Reveal for Option<T> {
    type Base = Option<T::Base>;
    fn reveal(self) -> Self::Base {
        self.map(|x| x.reveal())
    }
    fn from_public(other: Self::Base) -> Self {
        other.map(|x| <T as Reveal>::from_public(x))
    }
    fn from_add_shared(other: Self::Base) -> Self {
        other.map(|x| <T as Reveal>::from_add_shared(x))
    }
    fn unwrap_as_public(self) -> Self::Base {
        self
            .map(|x| Reveal::unwrap_as_public(x))
    }
    fn init_protocol() {
        T::init_protocol()
    }
    fn deinit_protocol() {
        T::deinit_protocol()
    }
}

impl<T: Reveal + Clone> Reveal for Rc<T>
where
    T::Base: Clone,
{
    type Base = Rc<T::Base>;
    fn reveal(self) -> Self::Base {
        Rc::new((*self).clone().reveal())
    }
    fn from_public(other: Self::Base) -> Self {
        Rc::new(Reveal::from_public((*other).clone()))
    }
    fn from_add_shared(other: Self::Base) -> Self {
        Rc::new(Reveal::from_add_shared((*other).clone()))
    }
    fn unwrap_as_public(self) -> Self::Base {
        Rc::new((*self).clone().unwrap_as_public())
    }
    fn init_protocol() {
        T::init_protocol()
    }
    fn deinit_protocol() {
        T::deinit_protocol()
    }
}

impl<A: Reveal, B: Reveal> Reveal for (A, B) {
    type Base = (A::Base, B::Base);
    fn reveal(self) -> Self::Base {
        (self.0.reveal(), self.1.reveal())
    }
    fn from_public(other: Self::Base) -> Self {
        (
            <A as Reveal>::from_public(other.0),
            <B as Reveal>::from_public(other.1),
        )
    }
    fn from_add_shared(other: Self::Base) -> Self {
        (
            <A as Reveal>::from_add_shared(other.0),
            <B as Reveal>::from_add_shared(other.1),
        )
    }
    fn unwrap_as_public(self) -> Self::Base {
        (self.0.unwrap_as_public(), self.1.unwrap_as_public())
    }
    fn init_protocol() {
        A::init_protocol();
        B::init_protocol();
    }

    fn deinit_protocol() {
        A::deinit_protocol();
        B::deinit_protocol();
    }
}

#[macro_export]
macro_rules! struct_reveal_impl {
    ($s:ty, $con:tt ; $( ($x_ty:ty, $x:tt) ),*) => {
        fn reveal(self) -> Self::Base {
            $con {
                $(
                    $x: self.$x.reveal(),
                )*
            }
        }
        fn from_public(other: Self::Base) -> Self {
            $con {
                $(
                    $x: <$x_ty as Reveal>::from_public(other.$x),
                )*
            }
        }
        fn from_add_shared(other: Self::Base) -> Self {
            $con {
                $(
                    $x: <$x_ty as Reveal>::from_add_shared(other.$x),
                )*
            }
        }
        fn unwrap_as_public(self) -> Self::Base {
            $con {
                $(
                    $x: self.$x.unwrap_as_public(),
                )*
            }
        }
    }
}

#[macro_export]
macro_rules! struct_reveal_simp_impl {
    ($con:path ; $( $x:tt ),*) => {
        fn reveal(self) -> Self::Base {
            $con {
                $(
                    $x: self.$x.reveal(),
                )*
            }
        }
        fn from_public(other: Self::Base) -> Self {
            $con {
                $(
                    $x: Reveal::from_public(other.$x),
                )*
            }
        }
        fn from_add_shared(other: Self::Base) -> Self {
            $con {
                $(
                    $x: Reveal::from_add_shared(other.$x),
                )*
            }
        }
        fn unwrap_as_public(self) -> Self::Base {
            $con {
                $(
                    $x: self.$x.unwrap_as_public(),
                )*
            }
        }
    }
}

#[macro_export]
macro_rules! dbg_disp {
    ($e:expr) => {
        println!("{}: {}", std::stringify!($e), &$e)
    }
}

#![macro_use]
use ark_std::{collections::BTreeMap, marker::PhantomData, rc::Rc};

pub trait Reveal {
    type Base;
    fn reveal(self) -> Self::Base;
    fn from_add_shared(b: Self::Base) -> Self;
    fn from_public(b: Self::Base) -> Self;
    //fn as_public_or_add_share(self) -> Result<Self::Base, Self::Base>;
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
    }
}

pub mod channel;
pub mod ss;


#![feature(associated_type_defaults)]

use std::borrow::Cow;
use std::marker::PhantomData;
use std::rc::Rc;
use std::collections::BTreeMap;

pub trait MpcWire: Clone {
    type Public = Self;
    fn publicize(&mut self) {}
    fn set_shared(&mut self, _shared: bool) {}
    fn is_shared(&self) -> bool {
        false
    }

    fn publicize_cow<'b>(&'b self) -> Cow<'b, Self> {
        if self.is_shared() {
            let mut s = self.clone();
            s.publicize();
            Cow::Owned(s)
        } else {
            Cow::Borrowed(self)
        }
    }

    fn cast_to_shared(&mut self) {
        self.set_shared(true);
    }

    fn cast_to_public(&mut self) {
        self.set_shared(false);
    }
}


impl<T> MpcWire for std::marker::PhantomData<T> {}

impl<A: MpcWire, B: MpcWire> MpcWire for (A, B) {
    struct_mpc_wire_impl!((A, B); (A, 0), (B, 1));
}
impl<A: MpcWire, B: MpcWire, C: MpcWire> MpcWire for (A, B, C) {
    struct_mpc_wire_impl!((A, B, C); (A, 0), (B, 1), (C, 2));
}
impl<A: MpcWire, B: MpcWire, C: MpcWire, D: MpcWire> MpcWire for (A, B, C, D) {
    struct_mpc_wire_impl!((A, B, C, D); (A, 0), (B, 1), (C, 2), (D, 3));
}

impl<T: MpcWire> MpcWire for Vec<T> {
    fn publicize(&mut self) {
        for x in self {
            x.publicize();
        }
    }
    fn set_shared(&mut self, shared: bool) {
        for x in self {
            x.set_shared(shared);
        }
    }
    fn is_shared(&self) -> bool {
        for x in self {
            if x.is_shared() {
                return true;
            }
        }
        false
    }
}

impl<T: MpcWire> MpcWire for Option<T> {
    fn publicize(&mut self) {
        for x in self {
            x.publicize();
        }
    }
    fn set_shared(&mut self, shared: bool) {
        for x in self {
            x.set_shared(shared);
        }
    }
    fn is_shared(&self) -> bool {
        for x in self {
            if x.is_shared() {
                return true;
            }
        }
        false
    }
}

#[macro_export]
macro_rules! struct_mpc_wire_impl {
    // struct_mpc_wire_impl!(STRUCT; FIELD1, FIELD2, ..., FIELDN);
    //
    // Use inside an impl block with the right bounds
    ($s:ty; $( ($x_ty:ty, $x:tt) ),*) => {
        fn publicize(&mut self) {
            $(
                self.$x.publicize();
            )*
        }
        fn set_shared(&mut self, shared: bool) {
            $(
                self.$x.set_shared(shared);
            )*
        }
        fn is_shared(&self) -> bool {
            $(
                if self.$x.is_shared() {
                    return true;
                }
            )*
            false
        }
    }
}

#[macro_export]
macro_rules! struct_mpc_wire_simp_impl {
    // struct_mpc_wire_impl!(STRUCT; FIELD1, FIELD2, ..., FIELDN);
    //
    // Use inside an impl block with the right bounds
    ($s:ty; $( $x:tt ),*) => {
        fn publicize(&mut self) {
            $(
                self.$x.publicize();
            )*
        }
        fn set_shared(&mut self, shared: bool) {
            $(
                self.$x.set_shared(shared);
            )*
        }
        fn is_shared(&self) -> bool {
            $(
                if self.$x.is_shared() {
                    return true;
                }
            )*
            false
        }
    }
}

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

//    fn as_public_or_add_share(self) -> Result<Self::Base, Self::Base> {
//        Ok(self)
//    }

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

//    fn as_public_or_add_share(self) -> Result<Self::Base, Self::Base> {
//        Ok(PhantomData::default())
//    }


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
//    fn as_public_or_add_share(self) -> Result<Self::Base, Self::Base> {
//        let mut out = Vec::new();
//        let mut shared = None;
//        for s in self {
//            match s.as_public_or_add_share() {
//                Ok(l) => {
//                    if shared == Some(true) {
//                        panic!("Heterogenous share")
//                    } else {
//                        shared = Some(false);
//                        out.push(l);
//                    }
//                }
//                Err(l) => {
//                    if shared == Some(false) {
//                        panic!("Heterogenous share")
//                    } else {
//                        shared = Some(true);
//                        out.push(l);
//                    }
//                }
//            }
//        }
//        match shared {
//            Some(true) => Err(out),
//            Some(false) => Ok(out),
//            None => Ok(Vec::new()),
//        }
//    }
    fn from_add_shared(other: Self::Base) -> Self {
        other
            .into_iter()
            .map(|x| <T as Reveal>::from_add_shared(x))
            .collect()
    }
}

impl<K: Reveal + Ord, V: Reveal> Reveal for BTreeMap<K, V>
where K::Base: Ord
{
    type Base = BTreeMap<K::Base, V::Base>;
    fn reveal(self) -> Self::Base {
        self.into_iter().map(|x| x.reveal()).collect()
    }
    fn from_public(other: Self::Base) -> Self {
        other
            .into_iter()
            .map(|x| Reveal::from_public(x))
            .collect()
    }
    fn from_add_shared(other: Self::Base) -> Self {
        other
            .into_iter()
            .map(|x| Reveal::from_add_shared(x))
            .collect()
    }
//    fn as_public_or_add_share(self) -> Result<Self::Base, Self::Base> {
//        let v: Vec<_> = self.into_iter().collect();
//        v.as_public_or_add_share()
//            .map(|s| s.into_iter().collect())
//            .map_err(|s| s.into_iter().collect())
//    }
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
//    fn as_public_or_add_share(self) -> Result<Self::Base, Self::Base> {
//        match self {
//            Some(s) => s.as_public_or_add_share().map(Some).map_err(Some),
//            None => Ok(None),
//        }
//    }
}

impl<T: Reveal + Clone> Reveal for Rc<T> where T::Base: Clone {
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
//    fn as_public_or_add_share(self) -> Result<Self::Base, Self::Base> {
//        (*self).clone().as_public_or_add_share().map(Rc::new).map_err(Rc::new)
//    }
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
//    fn as_public_or_add_share(self) -> Result<Self::Base, Self::Base> {
//        match (self.0.as_public_or_add_share(), self.1.as_public_or_add_share()) {
//            (Ok(a), Ok(b)) => Ok((a, b)),
//            (Err(a), Err(b)) => Err((a, b)),
//            _ => panic!("heterogenous"),
//        }
//    }

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


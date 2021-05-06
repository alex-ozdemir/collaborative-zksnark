use std::borrow::Cow;

pub trait MpcWire: Clone {
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

pub trait Reveal: MpcWire {
    type Base;
    fn reveal(self) -> Self::Base;
    fn obscure(b: Self::Base) -> Self;
}

impl<T> MpcWire for std::marker::PhantomData<T> {}

impl<A: MpcWire, B: MpcWire> MpcWire for (A, B) {
    struct_mpc_wire_impl!((A, B); (A, 0), (A, 1));
}

impl<A: Reveal, B: Reveal> Reveal for (A, B) {
    type Base = (A::Base, B::Base);
    fn reveal(self) -> Self::Base {
        (self.0.reveal(), self.1.reveal())
    }
    fn obscure(other: Self::Base) -> Self {
        (
            <A as Reveal>::obscure(other.0),
            <B as Reveal>::obscure(other.1),
        )
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
macro_rules! struct_reveal_impl {
    ($s:ty, $con:tt ; $( ($x_ty:ty, $x:tt) ),*) => {
        fn reveal(self) -> Self::Base {
            $con {
                $(
                    $x: self.$x.reveal(),
                )*
            }
        }
        fn obscure(other: Self::Base) -> Self {
            $con {
                $(
                    $x: <$x_ty as Reveal>::obscure(other.$x),
                )*
            }
        }
    }
}

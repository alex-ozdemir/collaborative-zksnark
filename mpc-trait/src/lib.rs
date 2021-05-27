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


impl<T> MpcWire for std::marker::PhantomData<T> {}

impl<A: MpcWire, B: MpcWire> MpcWire for (A, B) {
    struct_mpc_wire_impl!((A, B); (A, 0), (A, 1));
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


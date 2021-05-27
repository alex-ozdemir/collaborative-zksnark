#![macro_use]

macro_rules! impl_basics_2 {
    ($share:ident, $bound:ident, $wrap:ident) => {
        impl<T: $bound, S: $share<T>> $wrap<T, S> {
            pub fn new(t: T, shared: bool) -> Self {
                if shared {
                    Self::Shared(S::from_public(t))
                } else {
                    Self::Public(t)
                }
            }
            pub fn from_public(t: T) -> Self {
                Self::new(t, false)
            }
            pub fn unwrap_as_public(self) -> T {
                match self {
                    Self::Shared(s) => s.unwrap_as_public(),
                    Self::Public(s) => s,
                }
            }
            pub fn map<TT: $bound, SS: $share<TT>, FT: Fn(T) -> TT, FS: Fn(S) -> SS>(
                self,
                ft: FT,
                fs: FS,
            ) -> $wrap<TT, SS> {
                match self {
                    Self::Shared(s) => $wrap::Shared(fs(s)),
                    Self::Public(s) => $wrap::Public(ft(s)),
                }
            }
        }
        impl<T: $bound, S: $share<T>> Display for $wrap<T, S> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                match self {
                    $wrap::Public(x) => write!(f, "{} (shared)", x),
                    $wrap::Shared(x) => write!(f, "{} (public)", x),
                }
            }
        }
        impl<T: $bound, S: $share<T>> ToBytes for $wrap<T, S> {
            fn write<W: Write>(&self, _writer: W) -> io::Result<()> {
                unimplemented!("write")
            }
        }
        impl<T: $bound, S: $share<T>> FromBytes for $wrap<T, S> {
            fn read<R: Read>(_reader: R) -> io::Result<Self> {
                unimplemented!("read")
            }
        }
        impl<T: $bound, S: $share<T>> CanonicalSerialize for $wrap<T, S> {
            fn serialize<W: Write>(&self, _writer: W) -> Result<(), SerializationError> {
                unimplemented!("serialize")
            }
            fn serialized_size(&self) -> usize {
                unimplemented!("serialized_size")
            }
        }
        impl<T: $bound, S: $share<T>> CanonicalSerializeWithFlags for $wrap<T, S> {
            fn serialize_with_flags<W: Write, F: Flags>(
                &self,
                _writer: W,
                _flags: F,
            ) -> Result<(), SerializationError> {
                unimplemented!("serialize_with_flags")
            }

            fn serialized_size_with_flags<F: Flags>(&self) -> usize {
                unimplemented!("serialized_size_with_flags")
            }
        }
        impl<T: $bound, S: $share<T>> CanonicalDeserialize for $wrap<T, S> {
            fn deserialize<R: Read>(_reader: R) -> Result<Self, SerializationError> {
                unimplemented!("deserialize")
            }
        }
        impl<T: $bound, S: $share<T>> CanonicalDeserializeWithFlags for $wrap<T, S> {
            fn deserialize_with_flags<R: Read, F: Flags>(
                _reader: R,
            ) -> Result<(Self, F), SerializationError> {
                unimplemented!("deserialize_with_flags")
            }
        }
        impl<T: $bound, S: $share<T>> UniformRand for $wrap<T, S> {
            fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
                Self::Shared(<S as UniformRand>::rand(rng))
            }
        }
        impl<T: $bound, S: $share<T>> Add for $wrap<T, S> {
            type Output = Self;
            fn add(self, other: Self) -> Self::Output {
                match (self, other) {
                    ($wrap::Public(x), $wrap::Public(y)) => $wrap::Public(x + y),
                    ($wrap::Shared(x), $wrap::Public(y)) => $wrap::Shared(x.shift(&y)),
                    ($wrap::Public(x), $wrap::Shared(y)) => $wrap::Shared(y.shift(&x)),
                    ($wrap::Shared(x), $wrap::Shared(y)) => $wrap::Shared(x.add(&y)),
                }
            }
        }
        impl<T: $bound, S: $share<T>> Sum for $wrap<T, S> {
            fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
                iter.fold(Self::zero(), Add::add)
            }
        }
        impl<'a, T: $bound, S: $share<T> + 'a> Sum<&'a $wrap<T, S>> for $wrap<T, S> {
            fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
                iter.fold(Self::zero(), |x, y| x.add(y.clone()))
            }
        }
        impl<T: $bound, S: $share<T>> Neg for $wrap<T, S> {
            type Output = Self;
            fn neg(self) -> Self::Output {
                match self {
                    $wrap::Public(x) => $wrap::Public(-x),
                    $wrap::Shared(x) => $wrap::Shared(x.neg()),
                }
            }
        }
        impl<T: $bound, S: $share<T>> Sub for $wrap<T, S> {
            type Output = Self;
            fn sub(self, other: Self) -> Self::Output {
                match (self, other) {
                    ($wrap::Public(x), $wrap::Public(y)) => $wrap::Public(x - y),
                    ($wrap::Shared(x), $wrap::Public(y)) => $wrap::Shared(x.shift(&-y)),
                    ($wrap::Public(x), $wrap::Shared(y)) => $wrap::Shared(y.neg().shift(&x)),
                    ($wrap::Shared(x), $wrap::Shared(y)) => $wrap::Shared(x.sub(y)),
                }
            }
        }
        impl<T: $bound, S: $share<T>> Zero for $wrap<T, S> {
            fn zero() -> Self {
                $wrap::Public(T::zero())
            }
            fn is_zero(&self) -> bool {
                match self {
                    $wrap::Public(x) => x.is_zero(),
                    $wrap::Shared(_x) => unimplemented!("is_zero"),
                }
            }
        }
        impl<T: $bound, S: $share<T>> Zeroize for $wrap<T, S> {
            fn zeroize(&mut self) {
                *self = $wrap::Public(T::zero());
            }
        }
        impl<T: $bound, S: $share<T>> Default for $wrap<T, S> {
            fn default() -> Self {
                Self::zero()
            }
        }
    };
}

macro_rules! impl_ref_ops {
    ($op:ident, $assop:ident, $opfn:ident, $assopfn:ident, $bound:ident, $share:ident, $wrap:ident) => {
        impl<'a, T: $bound, S: $share<T>> $op<&'a $wrap<T, S>> for $wrap<T, S> {
            type Output = Self;
            fn $opfn(self, other: &$wrap<T, S>) -> Self::Output {
                self.$opfn(other.clone())
            }
        }
        impl<T: $bound, S: $share<T>> $assop<$wrap<T, S>> for $wrap<T, S> {
            fn $assopfn(&mut self, other: $wrap<T, S>) {
                *self = self.clone().$opfn(other.clone());
            }
        }
        impl<'a, T: $bound, S: $share<T>> $assop<&'a $wrap<T, S>> for $wrap<T, S> {
            fn $assopfn(&mut self, other: &$wrap<T, S>) {
                *self = self.clone().$opfn(other.clone());
            }
        }
    };
}

macro_rules! from_prim {
    ($t:ty, $bound:ident, $share:ident, $wrap:ident) => {
        impl<T: $bound, S: $share<T>> std::convert::From<$t> for $wrap<T, S> {
            fn from(t: $t) -> Self {
                $wrap::from_public(T::from(t))
            }
        }
    };
}


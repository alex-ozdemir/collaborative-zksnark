use std::borrow::Cow;

pub trait MpcWire: Clone {
    fn publicize(&mut self) {}
    fn cast_to_shared(&mut self) {}
    fn cast_to_public(&mut self) {}
    fn is_shared(&self) -> bool { false }
    fn publicize_cow<'b>(&'b self) -> Cow<'b, Self> {
        Cow::Borrowed(self)
    }
}

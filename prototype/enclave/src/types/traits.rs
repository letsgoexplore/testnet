// return a reasonable zero value
pub trait Zero {
    fn zero() -> Self;
}

// various functions for computing a.xor(b)
pub trait Xor {
    fn xor(&self, other: &Self) -> Self;
    fn xor_mut(&mut self, other: &Self)
    where
        Self: Sized,
    {
        *self = self.xor(other);
    }
}

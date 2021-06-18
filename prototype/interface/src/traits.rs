pub trait Size {
    fn size() -> usize;
    fn size_marshaled() -> usize;
}

impl<T> Size for T {
    fn size() -> usize {
        std::mem::size_of::<T>()
    }

    fn size_marshaled() -> usize {
        // TODO: we heuristically believe that our marshaling scheme has an expansion ratio < 2
        std::mem::size_of::<T>() * 2
    }
}


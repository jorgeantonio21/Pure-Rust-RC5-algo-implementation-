use std::convert::TryInto;

// represents either one of the types `u16`, `u32` or `u64`
pub trait Unsigned16To64 {
    type Bytes: Clone + Copy + AsRef<[u8]> + AsMut<[u8]>;
    fn copy_from_slice(plaintext: &[u8], start: usize, end: usize) -> Self::Bytes;
    fn from_le_bytes(bytes: Self::Bytes) -> Self;
    fn to_le_bytes(self) -> Self::Bytes;
    fn wrapping_add(self, other: Self) -> Self;
    fn wrapping_sub(self, other: Self) -> Self;
    fn wrapping_mul(self, other: Self) -> Self;
    fn rotate_left(self, other: Self) -> Self;
    fn rotate_right(self, other: Self) -> Self;
    fn xor(self, other: Self) -> Self;
    fn min() -> Self;
    fn from_str_radix(val: &str, base: u32) -> Self;
    fn from_usize(val: usize) -> Self;
    fn to_usize(&self) -> usize;
}

macro_rules! impl_unsigned_16_to_64 {
    ($($ty:ty),*) => { $(
        impl Unsigned16To64 for $ty {
            type Bytes = [u8; std::mem::size_of::<Self>()];

            fn copy_from_slice(plaintext: &[u8], start: usize, end: usize) -> Self::Bytes {
                let mut output = [0u8; std::mem::size_of::<Self>()];
                output.copy_from_slice(plaintext[start..end].as_ref());
                output
            }

            fn from_le_bytes(bytes: Self::Bytes) -> Self {
                <$ty>::from_le_bytes(bytes)
            }

            fn to_le_bytes(self) -> Self::Bytes {
                self.to_le_bytes()
            }

            fn wrapping_add(self, other: Self) -> Self {
                self.wrapping_add(other)
            }

            fn wrapping_sub(self, other: Self) -> Self {
                self.wrapping_sub(other)
            }

            fn wrapping_mul(self, other: Self) -> Self {
                self.wrapping_mul(other)
            }

            fn rotate_left(self, other: Self) -> Self {
                self.rotate_left(other.try_into().unwrap())
            }

            fn rotate_right(self, other: Self) -> Self {
                self.rotate_right(other.try_into().unwrap())
            }

            fn xor(self, other: Self) -> Self {
                self ^ other
            }

            fn min() -> Self {
                Self::MIN
            }

            fn from_str_radix(val: &str, base: u32) -> Self {
                Self::from_str_radix(val, base).unwrap()
            }

            fn from_usize(val: usize) -> Self {
                val as Self
            }

            fn to_usize(&self) -> usize {
                *self as usize
            }
        }
    )* }
}
impl_unsigned_16_to_64!(u16, u32, u64);

pub trait CipherMagicConstants {
    const P_W: &'static str;
    const Q_W: &'static str;
}

impl CipherMagicConstants for u16 {
    const P_W: &'static str = "b7e1"; // first magic number
    const Q_W: &'static str = "9e37"; // second magic number
}

impl CipherMagicConstants for u32 {
    const P_W: &'static str = "b7e15163"; // first magic number
    const Q_W: &'static str = "9e3779b9"; // second magic number
}

impl CipherMagicConstants for u64 {
    const P_W: &'static str = "b7e151628aed2a6b"; // fist magic number
    const Q_W: &'static str = "9e3779b97f47c15"; // second magic number
}

pub trait Rc5CipherStream<T: Unsigned16To64> {
    fn encode(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, &'static str>;
    fn decode(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, &'static str>;
    fn generate_block_cipher(&self) -> Vec<T>;
}

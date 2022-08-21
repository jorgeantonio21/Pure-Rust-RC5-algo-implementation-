use std::cmp::max;
use std::marker::PhantomData;
use traits::{CipherMagicConstants, Rc5CipherStream, Unsigned16To64};
mod traits;

struct RC5<T: Unsigned16To64> {
    key: Vec<u8>,
    words: usize,
    rounds: usize,
    bytes: usize,
    data: PhantomData<T>,
}

impl<T: Unsigned16To64> RC5<T> {
    #[allow(dead_code)]
    fn new(key: Vec<u8>, words: usize, rounds: usize, bytes: usize) -> Self {
        RC5 {
            key,
            words,
            rounds,
            bytes,
            data: PhantomData,
        }
    }
}

impl<T: Unsigned16To64 + CipherMagicConstants + Copy> Rc5CipherStream<T> for RC5<T> {
    fn encode(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, &'static str> {
        if self.key.len() != self.bytes {
            return Err("invalid encryption key length");
        }
        // get A block
        let mut a_block = T::copy_from_slice(&plaintext, 0usize, self.words);
        let mut a_from_le_bytes = T::from_le_bytes(a_block);

        // get B block
        let mut b_block = T::copy_from_slice(&plaintext, self.words, plaintext.len());
        let mut b_from_le_bytes = T::from_le_bytes(b_block);

        // let s table
        let s_table = self.generate_block_cipher();

        // initialize encryption of blocks A and B
        a_from_le_bytes = a_from_le_bytes.wrapping_add(s_table[0]);
        b_from_le_bytes = b_from_le_bytes.wrapping_add(s_table[1]);

        // the algorithm uses ROUNDS iterations, but it starts with a zeroth evaluation first
        for i in 1..(self.rounds + 1) {
            a_from_le_bytes = (a_from_le_bytes.xor(b_from_le_bytes))
                .rotate_left(b_from_le_bytes)
                .wrapping_add(s_table[2 * i]);
            b_from_le_bytes = (b_from_le_bytes.xor(a_from_le_bytes))
                .rotate_left(a_from_le_bytes)
                .wrapping_add(s_table[2 * i + 1]);
        }

        a_block = a_from_le_bytes.to_le_bytes();
        b_block = b_from_le_bytes.to_le_bytes();

        let mut ciphertext = Vec::new();
        ciphertext.extend_from_slice(a_block.as_ref());
        ciphertext.extend_from_slice(b_block.as_ref());
        Ok(ciphertext)
    }

    fn decode(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, &'static str> {
        if self.key.len() != self.bytes {
            return Err("invalid decryption key length");
        }

        // get A block
        let mut a_block = T::copy_from_slice(&plaintext, 0usize, self.words);
        let mut a_from_le_bytes = T::from_le_bytes(a_block);

        // get B block
        let mut b_block = T::copy_from_slice(&plaintext, self.words, plaintext.len());
        let mut b_from_le_bytes = T::from_le_bytes(b_block);

        // get s table
        let s_table = self.generate_block_cipher();

        // the algorithm uses ROUND iterations, but it starts with a zeroth evaluation first
        for i in (1..(self.rounds + 1)).rev() {
            b_from_le_bytes = b_from_le_bytes
                .wrapping_sub(s_table[2 * i + 1])
                .rotate_right(a_from_le_bytes)
                .xor(a_from_le_bytes);
            a_from_le_bytes = a_from_le_bytes
                .wrapping_sub(s_table[2 * i])
                .rotate_right(b_from_le_bytes)
                .xor(b_from_le_bytes);
        }

        // last iteration
        a_from_le_bytes = a_from_le_bytes.wrapping_sub(s_table[0]);
        b_from_le_bytes = b_from_le_bytes.wrapping_sub(s_table[1]);

        a_block = a_from_le_bytes.to_le_bytes();
        b_block = b_from_le_bytes.to_le_bytes();

        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(a_block.as_ref());
        plaintext.extend_from_slice(b_block.as_ref());

        Ok(plaintext)
    }

    fn generate_block_cipher(&self) -> Vec<T> {
        // by the protocol design, we are guaranteed that the length of the
        // key block is less than 255 = 2^8 - 1
        let mut l = if self.key.is_empty() {
            vec![T::min()]
        } else {
            (0..(self.key.len() as u8))
                .collect::<Vec<u8>>()
                .into_iter()
                .step_by(self.words)
                .map(|i| {
                    let slice = T::copy_from_slice(&self.key, i as usize, i as usize + 4);
                    T::from_le_bytes(slice)
                })
                .collect::<Vec<T>>()
        };

        let p_w = T::from_str_radix(T::P_W, 16); // first magic number
        let q_w = T::from_str_radix(T::Q_W, 16); // second magic number

        let s_table = 0..(2 * (self.rounds + 1));
        let mut s_table = s_table
            .into_iter()
            .map(|x| T::from_usize(x).wrapping_mul(q_w).wrapping_add(p_w))
            .collect::<Vec<T>>();

        let mut i = T::min().to_usize();
        let mut j = T::min().to_usize();

        let mut a_block = T::min();
        let mut b_block = T::min();

        let l_len = l.len();
        let s_len = s_table.len();

        let max_iters = max(s_len, l_len);

        for _ in 0..(3 * max_iters) {
            a_block = s_table[i]
                .wrapping_add(a_block)
                .wrapping_add(b_block)
                .rotate_left(T::from_usize(3usize));
            b_block = (l[j].wrapping_add(a_block).wrapping_add(b_block))
                .rotate_left(a_block.wrapping_add(b_block));

            s_table[i] = a_block;
            l[j] = b_block;

            i = (i + 1) % s_len;
            j = (j + 1) % l_len;
        }

        s_table
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const WORDS: usize = 4; // 4-bytes long, or 32-bit long
    const ROUNDS: usize = 12; // 1 round total
    const BYTES: usize = 16; // Key generation of length 10-bytes

    #[test]
    fn encode_a() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];

        let rc_5 = RC5::<u32>::new(key, WORDS, ROUNDS, BYTES);

        let pt = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let ct = vec![0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E];
        let res = rc_5.encode(pt).unwrap();
        assert_eq!(ct, res);
    }

    #[test]
    fn encode_b() {
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];

        let rc_5 = RC5::<u32>::new(key, WORDS, ROUNDS, BYTES);

        let pt = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let ct = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];
        let res = rc_5.encode(pt).unwrap();
        assert_eq!(ct, res);
    }

    #[test]
    fn decode_a() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];

        let rc_5 = RC5::<u32>::new(key, WORDS, ROUNDS, BYTES);

        let pt = vec![0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62];
        let ct = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let res = rc_5.decode(ct).unwrap();
        assert!(&pt[..] == &res[..]);
    }

    #[test]
    fn decode_b() {
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];

        let rc_5 = RC5::<u32>::new(key, WORDS, ROUNDS, BYTES);

        let pt = vec![0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B, 0x66, 0x3F];
        let ct = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let res = rc_5.decode(ct).unwrap();
        assert!(&pt[..] == &res[..]);
    }
}

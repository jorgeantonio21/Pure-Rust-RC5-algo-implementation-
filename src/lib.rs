use std::cmp::max;

const VERSION: usize = 1; // version 1
const WORDS: usize = 4; // 4-bytes long, or 32-bit long
const ROUNDS: usize = 12; // 1 round total
const BYTES: usize = 16; // Key generation of length 10-bytes

/*
 * This function should return a cipher text for a given key and plaintext
 *
 */
fn encode(key: Vec<u8>, plaintext: Vec<u8>) -> Result<Vec<u8>, &'static str> {
    if key.len() != BYTES {
        return Err("invalid encryption key length");
    }
    // get A block
    let mut a_block = [0u8; 4];
    a_block.copy_from_slice(&plaintext[..WORDS]);
    let mut a_from_le_bytes = u32::from_le_bytes(a_block);

    // get B block
    let mut b_block = [0u8; 4];
    b_block.copy_from_slice(&plaintext[WORDS..]);
    let mut b_from_le_bytes = u32::from_le_bytes(b_block);

    // let s table
    let s_table = generate_block_cipher(key);

	// initialize encryption of blocks A and B
	a_from_le_bytes = a_from_le_bytes.wrapping_add(s_table[0]);
	b_from_le_bytes = b_from_le_bytes.wrapping_add(s_table[1]);

    // the algorithm uses ROUNDS iterations, but it starts with a zeroth evaluation first
    for i in 1..(ROUNDS + 1) {
        a_from_le_bytes = (a_from_le_bytes ^ b_from_le_bytes)
            .rotate_left(b_from_le_bytes)
            .wrapping_add(s_table[2 * i]);
        b_from_le_bytes = (b_from_le_bytes ^ a_from_le_bytes)
            .rotate_left(a_from_le_bytes)
            .wrapping_add(s_table[2 * i + 1]);
    }

    a_block = a_from_le_bytes.to_le_bytes();
    b_block = b_from_le_bytes.to_le_bytes();

    let mut ciphertext = Vec::new();
    ciphertext.extend_from_slice(&a_block);
    ciphertext.extend_from_slice(&b_block);
    Ok(ciphertext)
}

/*
 * This function should return a plaintext for a given key and ciphertext
 *
 */
fn decode(key: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>, &'static str> {
    if key.len() != BYTES {
        return Err("invalid decryption key length");
    }

    // get A block
    let mut a_block = [0u8; 4];
    a_block.copy_from_slice(&ciphertext[..WORDS]);
    let mut a_from_le_bytes = u32::from_le_bytes(a_block);

    // get B block
    let mut b_block = [0u8; 4];
    b_block.copy_from_slice(&ciphertext[WORDS..]);
    let mut b_from_le_bytes = u32::from_le_bytes(b_block);

    // get s table
    let s_table = generate_block_cipher(key);

    // the algorithm uses ROUND iterations, but it starts with a zeroth evaluation first
    for i in (1..(ROUNDS + 1)).rev() {
        b_from_le_bytes = b_from_le_bytes
            .wrapping_sub(s_table[2 * i + 1])
            .rotate_right(a_from_le_bytes)
            ^ a_from_le_bytes;
        a_from_le_bytes = a_from_le_bytes
            .wrapping_sub(s_table[2 * i])
            .rotate_right(b_from_le_bytes)
            ^ b_from_le_bytes;
    }

    // last iteration
    a_from_le_bytes = a_from_le_bytes.wrapping_sub(s_table[0]);
    b_from_le_bytes = b_from_le_bytes.wrapping_sub(s_table[1]);

    a_block = a_from_le_bytes.to_le_bytes();
    b_block = b_from_le_bytes.to_le_bytes();
	
    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(&a_block);
    plaintext.extend_from_slice(&b_block);

    Ok(plaintext)
}

/*
 * This function should return the key generation for the RC5 algorithm
 *
 */
fn generate_block_cipher(key: Vec<u8>) -> Vec<u32> {
    // by the protocol design, we are guaranteed that the length of the
    // key block is less than 255 = 2^8 - 1
    let mut l = if key.is_empty() {
        vec![0u32]
    } else {
        (0..(key.len() as u8))
            .collect::<Vec<u8>>()
            .into_iter()
            .step_by(WORDS)
            .map(|i| {
                let mut slice = [0u8; WORDS];
                slice.copy_from_slice(&key[(i as usize)..(i as usize + 4)]);
                u32::from_le_bytes(slice)
            })
            .collect::<Vec<u32>>()
    };

    let p_w = u32::from_str_radix("b7e15163", 16).unwrap(); // first magic number
    let q_w = u32::from_str_radix("9e3779b9", 16).unwrap(); // second magic number

    let s_table = 0..(2u32 * (ROUNDS as u32 + 1));
    let mut s_table = s_table
        .into_iter()
        .map(|x| x.wrapping_mul(q_w).wrapping_add(p_w))
        .collect::<Vec<u32>>();

    let mut i = 0u32;
    let mut j = 0u32;

    let mut a_block = 0u32;
    let mut b_block = 0u32;

    let l_len = l.len() as u32;
    let s_len = s_table.len() as u32;

    let max_iters = max(s_len, l_len);
    for _ in 0..(3 * max_iters) {
        a_block = s_table[i as usize]
            .wrapping_add(a_block)
            .wrapping_add(b_block)
            .rotate_left(3u32);
        b_block = (l[j as usize].wrapping_add(a_block).wrapping_add(b_block))
            .rotate_left(a_block.wrapping_add(b_block));

        s_table[i as usize] = a_block;
        l[j as usize] = b_block;

        i = (i + 1) % s_len;
        j = (j + 1) % l_len;
    }

    s_table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_a() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let ct = vec![0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E];
        let res = encode(key, pt).unwrap();
        assert_eq!(ct, res);
    }

    #[test]
    fn encode_b() {
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let pt = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let ct = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];
        let res = encode(key, pt).unwrap();
        assert_eq!(ct, res);
    }

    #[test]
    fn decode_a() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = vec![0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62];
        let ct = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let res = decode(key, ct).unwrap();
        assert!(&pt[..] == &res[..]);
    }

    #[test]
    fn decode_b() {
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let pt = vec![0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B, 0x66, 0x3F];
        let ct = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let res = decode(key, ct).unwrap();
        assert!(&pt[..] == &res[..]);
    }
}

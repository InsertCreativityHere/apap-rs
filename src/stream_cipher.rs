
use aes::Aes256;
use cipher::{BlockEncrypt, Key, KeyInit};
use rayon::prelude::*;

/// An implementation of an AES-256 CTR cipher.
#[derive(Debug)]
pub struct StreamCipher {
    /// The underlying AES-256 implementation that this cipher uses internally.
    engine: Aes256,
}

impl StreamCipher {
    /// Create a new AES-256 cipher and initialize it with the specified key.
    pub fn initialize(key: &Key<Aes256>) -> Self {
        let engine = Aes256::new(key);
        Self { engine }
    }

    /// Encrypt/Decrypt the provided block with an AES-256 CTR encryption scheme.
    /// The block must be 16 bytes or less, since AES can only process 128 bits at a time.
    ///
    /// The provided counter value is encrypted with AES-256 and then XOR'd with the block.
    /// Because the XOR operation is an involution, applying this function twice will yield the original block.
    pub fn process_block(&self, counter: u128, block: &mut [u8]) {
        // AES can only handle blocks up to 128 bits (16 bytes) in length.
        debug_assert!(block.len() <= 16);

        // Encrypt the block's corresponding counter value.
        let mut counter_bytes = counter.to_be_bytes();
        self.engine.encrypt_block((&mut counter_bytes).into());

        // XOR the block with the encrypted counter value in-place.
        for i in 0..block.len() {
            block[i] ^= counter_bytes[i];
        }
    }

    /// Encrypt/Decrypt the provided blocks with an AES-256 CTR encryption scheme.
    /// For performance, this function requires each block to be exactly 16 bytes long, since AES operates on 128 bit
    /// blocks. For smaller blocks, use [Self::process_blocks] instead.
    ///
    /// The provided counter value is encrypted with AES-256 and then XOR'd with the block.
    /// Because the XOR operation is an involution, applying this function twice will yield the original block.
    pub fn process_blocks<'a>(&self, block_buffer: impl ParallelIterator<Item = (u128, &'a mut [u8; 16])>) {
        // Iterate through the (block, counter) pairs in parallel for efficiency.
        block_buffer.for_each(|(counter, block)| {
            // Encrypt the block's corresponding counter value.
            let mut counter_bytes = counter.to_be_bytes();
            self.engine.encrypt_block((&mut counter_bytes).into());

            // XOR the block with the encrypted counter value in-place.
            for i in 0..16 {
                block[i] ^= counter_bytes[i];
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::StreamCipher;
    use crate::key_gen_utils;
    use rand::Rng;
    use rayon::prelude::*;

    #[test]
    fn ensure_cipher_is_an_involution() {
        // ===== Arrange ===== //
        let plain_text = b"I am a test!".clone();

        let mut buffer = plain_text.clone();
        let iv: u128 = rand::thread_rng().gen();
        let test_key = key_gen_utils::generate_new_encryption_key();
        let stream_cipher = StreamCipher::initialize((&test_key).into());

        // ===== Act ===== //
        stream_cipher.process_block(iv, &mut buffer);
        stream_cipher.process_block(iv, &mut buffer);

        // ==== Assert ===== //
        assert_eq!(buffer, plain_text, "iv = '{iv:?}', key = '{test_key:?}");
    }

    #[test]
    fn ensure_correct_cipher_text_is_produced() {
        // ===== Arrange ===== //
        let plain_text = [ // "This is a really cool test yeah?"
            0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x72, 0x65, 0x61, 0x6C, 0x6C, 0x79,
            0x20, 0x63, 0x6F, 0x6F, 0x6C, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x79, 0x65, 0x61, 0x68, 0x3F,
        ];
        let test_key = [
            0x76, 0xD4, 0xCF, 0x3D, 0x6E, 0x60, 0x47, 0x63, 0x98, 0x4A, 0x12, 0xF4, 0xE4, 0x9F, 0x14, 0x4B,
            0x4F, 0x20, 0x0F, 0x7A, 0x8D, 0x54, 0xDC, 0x6D, 0xEB, 0x10, 0x2B, 0x67, 0xB5, 0xC4, 0x33, 0xE7,
        ];
        let stream_cipher = StreamCipher::initialize((&test_key).into());
        let mut test_buffer = plain_text.clone();
        let iv = 797979797979_u128;

        // ===== Act ===== //
        let plain_text_chunks: &mut [[u8; 16]] = unsafe { test_buffer.as_chunks_unchecked_mut() };
        stream_cipher.process_blocks(
            plain_text_chunks
                .into_par_iter()
                .enumerate()
                .map(|(index, block)| (index as u128 + iv, block))
        );

        // ===== Assert ===== //
        let expected_cipher_text = [
            0x66, 0xEA, 0x47, 0x5D, 0x9C, 0x17, 0xDB, 0x56, 0xDF, 0xF1, 0x95, 0x53, 0x9A, 0x43, 0xB5, 0xC1,
            0x4C, 0x7D, 0x6C, 0x55, 0x51, 0xCD, 0x69, 0x4C, 0x4A, 0xA2, 0x2B, 0xB0, 0xE1, 0xB2, 0xBC, 0xEA,
        ];
        assert_eq!(test_buffer, expected_cipher_text);
    }
}

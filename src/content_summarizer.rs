
use sha2::{Digest, Sha512};

/// This struct summarizes a sequence of bytes into 2 fields:
/// - the number of bytes
/// - an SHA-512 hash of the bytes
/// These two values allow users to know the length and validity of files before decrypting them.
#[derive(Debug, Default)]
pub struct ContentSummarizer {
    /// The underlying SHA-512 implementation that this cipher uses internally.
    hash_engine: Sha512,

    /// The number of bytes that have been hashed by this summarizer so far.
    content_length: u64,
}

impl ContentSummarizer {
    /// Update the summary with the provided bytes.
    /// These bytes are fed into the hash engine, and counted towards the content length.
    pub fn update(&mut self, contents: &[u8]) {
        self.hash_engine.update(contents);
        self.content_length += contents.len() as u64;
    }

    /// Generate a summary of the content that has been fed into this summarizer.
    ///
    /// The hash value includes the following fields, even though they are part of the ARH header, and not the content:
    /// `initial_counter_value`, `key_salt`, and `content_length` (in this specific order).
    /// This is done to provide increased tamper-resistance to the file's data.
    ///
    /// Note that the length of these fields still aren't counted towards the total `content_length`.
    pub fn finalize(mut self, initial_counter_value: u128, key_salt: u64) -> ([u8; 64], u64) {
        self.hash_engine.update(initial_counter_value.to_be_bytes());
        self.hash_engine.update(key_salt.to_be_bytes());
        self.hash_engine.update(self.content_length.to_be_bytes());

        (self.hash_engine.finalize().into(), self.content_length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn ensure_correct_summary_is_produced() {
        // ===== Arrange ===== //
        let content = (0..255).collect::<Vec<u8>>();
        let iv: u128 = 7979_7979_7979_7979_7979;
        let key_salt: u64 = 1014_0815_1112_0128;

        let mut summarizer = ContentSummarizer::default();

        // ===== Act ===== //
        summarizer.update(&content);
        let (hash, length) = summarizer.finalize(iv, key_salt);

        // ===== Assert ===== //
        let expected_hash = [
            0x2F, 0x5C, 0x54, 0x5B, 0x82, 0x81, 0xC0, 0x94, 0x49, 0xEB, 0xD0, 0xB4, 0xE0, 0x37, 0x84, 0x90,
            0x92, 0xAB, 0x86, 0x0E, 0xD7, 0x27, 0xED, 0x23, 0x48, 0xAA, 0x5B, 0xDF, 0x2A, 0x19, 0xEB, 0x4A,
            0xD8, 0x35, 0x56, 0x42, 0xA6, 0x46, 0x1E, 0xC1, 0x20, 0xEC, 0x7F, 0x27, 0x25, 0x0E, 0x0E, 0xC5,
            0xD7, 0xFB, 0x17, 0x3B, 0xDE, 0x3A, 0xAB, 0xA6, 0x6E, 0xCF, 0xAD, 0xBD, 0xFC, 0x72, 0x34, 0xB8,
        ];
        assert_eq!(hash, expected_hash);
        assert_eq!(length, 255);
    }

    #[test]
    fn hash_value_is_independent_of_slicing() {
        // ===== Arrange ===== //
        let content: [u8; 32] = rand::thread_rng().gen();
        let iv: u128 = rand::thread_rng().gen();
        let key_salt: u64 = rand::thread_rng().gen();

        let slice_point = rand::thread_rng().gen_range(0..32);
        let slice1 = &content[..slice_point];
        let slice2 = &content[slice_point..];

        let mut full_summarizer = ContentSummarizer::default();
        let mut slice_summarizer = ContentSummarizer::default();

        // ==== Act ==== //
        full_summarizer.update(&content);
        let full_summary = full_summarizer.finalize(iv, key_salt);

        slice_summarizer.update(slice1);
        slice_summarizer.update(slice2);
        let slice_summary = slice_summarizer.finalize(iv, key_salt);

        // ===== Assert ===== //
        assert_eq!(full_summary, slice_summary, "content = '{content:?}', iv = '{iv:?}', key_salt = '{key_salt:?}'");
    }
}

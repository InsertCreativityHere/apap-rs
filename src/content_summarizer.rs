
use sha2::{Digest, Sha512};

/// TODO
#[derive(Debug, Default)]
pub struct ContentSummarizer {
    /// The underlying SHA-512 implementation that this cipher uses internally.
    hash_engine: Sha512,

    /// The number of bytes that have been hashed by this summarizer so far.
    content_length: u64,
}

impl ContentSummarizer {
    /// Update the summary with the provided bytes of content.
    /// These bytes are fed into the hash engine, and counted towards the content length.
    pub fn update(&mut self, contents: &[u8]) {
        self.hash_engine.update(contents);
        self.content_length += contents.len() as u64;
    }

    /// Generate a summary of the content that has been fed into this summarizer.
    ///
    /// The hash value includes the following fields, even though they are part of the ARH header, and not the content.
    ///     `initial_counter_value`, `key_salt`, and `content_length`
    /// As such, the length of these fields aren't counted towards the total `content_length`.
    /// This is done to provide increased tamper-resistance to the file's data.
    pub fn finalize(mut self, initial_counter_value: u128, key_salt: u64) -> ([u8; 64], u64) {
        self.hash_engine.update(initial_counter_value.to_be_bytes());
        self.hash_engine.update(key_salt.to_be_bytes());
        self.hash_engine.update(self.content_length.to_be_bytes());

        (self.hash_engine.finalize().into(), self.content_length)
    }
}

#[test]
fn test_content_summarizer() {
    // TODO
}

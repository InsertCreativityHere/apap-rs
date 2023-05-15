
use super::utils::{read_to_buffer, ReadResult};
use std::fs::File;
use std::io::{Read, Result};
use std::path::Path;

pub struct PlainTextReader<T: Read> {
    input: T,
}

impl<T: Read> PlainTextReader<T> {
    pub fn new(input: T) -> Self {
        Self { input }
    }

    pub fn try_read_from(&mut self, buffer: &mut [u8]) -> ReadResult {
        read_to_buffer(&mut self.input, buffer)
    }
}

impl PlainTextReader<File> {
    pub fn open_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path)?;
        Ok(Self::new(file))
    }
}

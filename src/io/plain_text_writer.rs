
use std::fs::File;
use std::io::{Result, Write};
use std::path::Path;

pub struct PlainTextWriter<T: Write> {
    output: T,
}

impl<T: Write> PlainTextWriter<T> {
    pub fn new(output: T) -> Self {
        Self { output }
    }

    pub fn write_content(&mut self, content: &[u8]) -> Result<()> {
        self.output.write_all(content)
    }
}

impl PlainTextWriter<File> {
    pub fn create_new_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::create_new(path)?;
        Ok(Self::new(file))
    }
}

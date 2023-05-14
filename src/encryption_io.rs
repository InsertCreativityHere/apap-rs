
use crate::constants::*;
use crate::io_utils::{read_to_buffer, ReadResult};
use crate::Header;
use std::fs::File;
use std::io::{Error, ErrorKind, Read, Result, Seek, SeekFrom, Write};
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

impl PlainTextReader<std::fs::File> {
    pub fn open_from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let file = File::open(path)?;
        Ok(Self::new(file))
    }
}








pub struct CipherTextWriter<T: Write + Seek> {
    output: T,
}

impl<T: Seek + Write> CipherTextWriter<T> {
    pub fn new(mut output: T) -> Result<Self> {
        let offset = output.seek(SeekFrom::Start(FILE_HEADER_SIZE))?;
        if offset != FILE_HEADER_SIZE {
            let message =  format!("Failed to seek to content start! Expected to be at '{FILE_HEADER_SIZE}', but reached '{offset}'.");
            return Err(Error::new(ErrorKind::Other, message));
        }

        Ok(Self { output })
    }

    pub fn write_content(&mut self, content: &[u8]) -> Result<()> {
        self.output.write_all(content)
    }

    pub fn finalize(mut self, header: &Header) -> Result<()> {
        self.finalize_impl(header)
    }

    fn finalize_impl(&mut self, header: &Header) -> Result<()> {
        self.output.write_all(&FILE_END)?;

        let start_offset = self.output.seek(SeekFrom::Start(0))?;
        if start_offset != 0 {
            let message =  format!("Failed to seek to start! Expected to be at '0', but reached '{start_offset}'.");
            return Err(Error::new(ErrorKind::Other, message));
        }

        self.output.write_all(&FILE_BEG)?;
        self.output.write_all(&header.signature_key)?;
        self.output.write_all(&header.signature)?;
        self.output.write_all(&header.initial_counter_value.to_be_bytes())?;
        self.output.write_all(&header.encryption_key_salt.to_be_bytes())?;
        self.output.write_all(&header.content_length.to_be_bytes())?;

        let header_offset = self.output.stream_position()?;
        if header_offset != FILE_HEADER_SIZE {
            let message =  format!("Failed to write header! Expected to be at '{FILE_HEADER_SIZE}', but reached '{header_offset}'.");
            return Err(Error::new(ErrorKind::Other, message));
        }

        Ok(())
    }
}

impl CipherTextWriter<File> {
    pub fn create_new_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::create_new(path)?;
        Self::new(file)
    }

    pub fn finalize_and_sync(mut self, header: &Header) -> Result<()> {
        self.finalize_impl(header)?;
        self.output.sync_all()
    }
}

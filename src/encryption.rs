
use crate::constants::*;
use crate::io_utils::{read_to_buffer, ReadResult};
use crate::Header;
use std::fs::File;
use std::io::{Error, ErrorKind, Result, Seek, SeekFrom, Write};
use std::path::Path;

pub struct PlainFileReader {
    file: File,
}

impl PlainFileReader {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path)?;
        Ok(Self { file })
    }

    pub fn try_read_from(&mut self, buffer: &mut [u8]) -> ReadResult {
        read_to_buffer(&mut self.file, buffer)
    }
}

pub struct CipherFileWriter {
    file: File,
}

impl CipherFileWriter {
    pub fn create_new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = File::create_new(path)?;

        let offset = file.seek(SeekFrom::Start(FILE_HEADER_SIZE))?;
        if offset != FILE_HEADER_SIZE {
            let message =  format!("Failed to seek to content start! Expected to be at '{FILE_HEADER_SIZE}', but reached '{offset}'.");
            return Err(Error::new(ErrorKind::Other, message));
        }

        Ok(Self { file })
    }

    pub fn write_content(&mut self, content: &[u8]) -> Result<()> {
        self.file.write_all(content)
    }

    pub fn finalize(mut self, header: &Header) -> Result<()> {
        self.file.write_all(&FILE_END)?;

        let start_offset = self.file.seek(SeekFrom::Start(0))?;
        if start_offset != 0 {
            let message =  format!("Failed to seek to file start! Expected to be at '0', but reached '{start_offset}'.");
            return Err(Error::new(ErrorKind::Other, message));
        }

        self.file.write_all(&FILE_BEG)?;
        self.file.write_all(&header.signature_key)?;
        self.file.write_all(&header.signature)?;
        self.file.write_all(&header.initial_counter_value.to_be_bytes())?;
        self.file.write_all(&header.encryption_key_salt.to_be_bytes())?;
        self.file.write_all(&header.content_length.to_be_bytes())?;

        let header_offset = self.file.stream_position()?;
        if header_offset != FILE_HEADER_SIZE {
            let message =  format!("Failed to write header! Expected to be at '{FILE_HEADER_SIZE}', but reached '{header_offset}'.");
            return Err(Error::new(ErrorKind::Other, message));
        }

        self.file.sync_all()
    }
}

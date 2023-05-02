
use crate::constants::*;
use crate::io_utils::{read_to_buffer, ReadResult};
use std::fs::File;
use std::io::{Error, ErrorKind, Read, Result, Seek, Write};
use std::path::Path;




pub struct PlainFileWriter {
    file: File,
}

impl PlainFileWriter {
    pub fn create_new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::create_new(path)?;
        Ok(Self { file })
    }

    pub fn write_content(&mut self, content: &[u8]) -> Result<()> {
        self.file.write_all(content)
    }
}


pub struct Header {
    pub signature_key: [u8; 32],
    pub signature: [u8; 64],
    
    pub initial_counter_value: u128,
    pub encryption_key_salt: u64,

    pub content_length: u64,
}


pub struct CipherFileReader {
    file: File,
    header: Header,
}

impl CipherFileReader {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = File::open(path)?;

        let mut file_beg_marker = [0; 4];
        read_to_buffer(&mut file, &mut file_beg_marker).into_result()?;
        if file_beg_marker != FILE_BEG {
            let message = format!("File doesn't start with a `FILE_BEG` marker. Are you sure this is an ARH file?\n\tFound '{file_beg_marker:02X?}' instead.");
            return Err(Error::new(ErrorKind::InvalidData, message));
        }

        let mut signature_key = [0; 32];
        read_to_buffer(&mut file, &mut signature_key).into_result()?;

        let mut signature = [0; 64];
        read_to_buffer(&mut file, &mut signature).into_result()?;

        let mut initial_counter_value = [0; 16];
        read_to_buffer(&mut file, &mut initial_counter_value).into_result()?;
        let initial_counter_value = u128::from_be_bytes(initial_counter_value);

        let mut encryption_key_salt = [0; 8];
        read_to_buffer(&mut file, &mut encryption_key_salt).into_result()?;
        let encryption_key_salt = u64::from_be_bytes(encryption_key_salt);

        let mut content_length = [0; 8];
        read_to_buffer(&mut file, &mut content_length).into_result()?;
        let content_length = u64::from_be_bytes(content_length);

        let header_offset = file.stream_position()?;
        if header_offset != FILE_HEADER_SIZE {
            let message =  format!("Failed to read header! Expected to be at '{FILE_HEADER_SIZE}', but reached '{header_offset}'.");
            return Err(Error::new(ErrorKind::Other, message));
        }

        let header = Header { signature_key, signature, initial_counter_value, encryption_key_salt, content_length };
        Ok(Self { file, header })
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn try_read_from(&mut self, buffer: &mut [u8]) -> ReadResult {
        read_to_buffer(&mut self.file, buffer)
    }

    pub fn check_file_end(&mut self, expect_eof: bool) -> Result<()> {
        let mut buffer = [0; FILE_FOOTER_SIZE as usize];

        read_to_buffer(&mut self.file, &mut buffer).into_result()?;
        if buffer != FILE_END {
            let message = "File doesn't end with a `FILE_END` marker. Are you sure this is an ARH file?";
            return Err(Error::new(ErrorKind::InvalidData, message));
        }

        if expect_eof {
            match self.file.read(&mut buffer) {
                Ok(0) => Ok(()),
                Ok(_) => Err(Error::new(ErrorKind::Other, "Expected to be at EOF but more data was available.")),
                Err(error) => Err(error),
            }
        } else {
            Ok(())
        }
    }
}

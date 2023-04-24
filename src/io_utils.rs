
use std::io::{Error, ErrorKind, Read, Result};

/// TODO add comments to all of this stuff.
pub enum ReadResult {
    Full,
    EOF(usize),
    Error(Error)
}

/// TODO

/// TODO
pub fn read_to_buffer(reader: &mut impl Read, mut buffer: &mut [u8]) -> ReadResult {
    let initial_length = buffer.len();

    while !buffer.is_empty() {
        match reader.read(buffer) {
            Ok(0) => break, // EOF
            Ok(n) => buffer = &mut buffer[n..],
            Err(ref e) if e.kind() == ErrorKind::Interrupted => {},
            Err(e) => return ReadResult::Error(e),
        }
    }

    match buffer.len() {
        0 => ReadResult::Full,
        len => ReadResult::EOF(initial_length - len),
    }
}

// TODO add a test


use std::io::{Error, ErrorKind, Read};

/// This function attempts to fill the provided buffer with bytes read from the specified source.
///
/// It continues to call read on the source until:
/// - The buffer has been completely filled with data. In this case [`ReadResult::Full`] is returned.
/// - The end of the reader was hit before the buffer could be filled. In this case [`ReadResult::EOS`] is returned.
/// - An attempt to read fails with an error other than [`ErrorKind::Interrupted`].
///   In this case [`ReadResult::Error`] is returned. If this function encounters [`ErrorKind::Interrupted`],
///   it is ignored, and the source will be polled again for more data. 
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
        len => ReadResult::EOS(initial_length - len),
    }
}

/// This enum represents the possible results of calling [`read_to_buffer`].
#[derive(Debug)]
pub enum ReadResult {
    /// Indicates that the provided buffer was completely filled with data read from the source.
    Full,

    /// Indicates that End-Of-Stream was hit before the provided buffer could be completely filled.
    /// The associated value is the number of bytes that were read before hitting EOS.
    EOS(usize),

    /// An error was encountered while reading from the source.
    Error(Error)
}

#[cfg(test)]
mod tests {
    use super::{read_to_buffer, ReadResult};

    #[test]
    fn read_from_empty_stream_returns_eos() {
        // ===== Arrange ===== //
        let mut source = [69_u8; 0].as_slice();
        let mut buffer = [0_u8; 32];

        // ===== Act ===== //
        let result = read_to_buffer(&mut source, &mut buffer);

        // ===== Assert ===== //
        assert!(matches!(result, ReadResult::EOS(0)));
    }

    #[test]
    fn read_from_stream_thats_smaller_than_buffer_returns_eos() {
        // ===== Arrange ===== //
        let mut source = [79_u8; 8].as_slice();
        let mut buffer = [0_u8; 16];

        // ===== Act ===== //
        let result = read_to_buffer(&mut source, &mut buffer);

        // ===== Assert ===== //
        assert!(matches!(result, ReadResult::EOS(8)));
    }

    #[test]
    fn reaching_eos_returns_eos() {
        // ===== Arrange ===== //
        let mut source = [89_u8; 64].as_slice();
        let mut buffer = [ 0_u8; 40];

        let pre_result = read_to_buffer(&mut source, &mut buffer);
        assert!(matches!(pre_result, ReadResult::Full));

        // ===== Act ===== //
        let result = read_to_buffer(&mut source, &mut buffer);

        // ===== Assert ===== //
        assert!(matches!(result, ReadResult::EOS(24)));
    }

    #[test]
    fn attempting_to_read_past_eos_returns_eos() {
        // ===== Arrange ===== //
        let mut source = [99_u8; 20].as_slice();
        let mut buffer = [ 0_u8; 18];

        let pre_result = read_to_buffer(&mut source, &mut buffer);
        assert!(matches!(pre_result, ReadResult::Full));
        let pre_result = read_to_buffer(&mut source, &mut buffer);
        assert!(matches!(pre_result, ReadResult::EOS(2)));

        // ===== Act ===== //
        let result = read_to_buffer(&mut source, &mut buffer);

        // ===== Assert ===== //
        assert!(matches!(result, ReadResult::EOS(0)));
    }

    #[test]
    fn reading_exactly_to_eos_returns_fully() {
        // ===== Arrange ===== //
        let mut source = [9_u8; 12].as_slice();
        let mut buffer = [0_u8; 12];

        // ===== Act ===== //
        let result = read_to_buffer(&mut source, &mut buffer);

        // ===== Assert ===== //
        assert!(matches!(result, ReadResult::Full));
    }

    #[test]
    fn attempting_to_read_before_eos_returns_fully() {
        // ===== Arrange ===== //
        let mut source = [9_u8; 28].as_slice();
        let mut buffer = [0_u8; 20];

        // ===== Act ===== //
        let result = read_to_buffer(&mut source, &mut buffer);

        // ===== Assert ===== //
        assert!(matches!(result, ReadResult::Full));
    }
}

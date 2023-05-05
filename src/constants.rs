
/// Magic byte sequence that always appears as a marker at the beginning of ARH formatted files.
pub const FILE_BEG: [u8; 4] = [ 0x42, 0x6C, 0x28, 0x79 ];
/// Magic byte sequence that always appears as a marker at the end of ARH formatted files.
pub const FILE_END: [u8; 4] = [ 0x45, 0xC9, 0x0E, 0x79 ];

/// The number of bytes taken up by an ARH header.
pub const FILE_HEADER_SIZE: u64 =
    4 // FILE_BEG marker
 + 32 // public signing key
 + 64 // encrypted SHA512 hash
 + 16 // initial counter value 
 +  8 // AES key salt
 +  8 // content length
;
/// The number of bytes taken up by an ARH footer.
pub const FILE_FOOTER_SIZE: u64 =
    4 // FILE_END maker
;

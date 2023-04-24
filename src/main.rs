
#![feature(file_create_new)]
#![feature(slice_as_chunks)]

pub mod decryption;
pub mod encryption;
mod constants;
mod content_summarizer;
mod derived_key_data;
mod io_utils;
mod key_gen_utils;
mod signature_utils;
mod stream_cipher;

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use rand::Rng;

use aes::Aes256;
use cipher::Key;

// TODO add a license, README, cleanup the gitignore, and modify Cargo config file.

// TODO add module comments to things.
// TODO maybe zeroize other things?

// TODO should we test `ReadResult::Error`?

// ===========================================================================================
// Okay, I think that we have literally everything we need now to implement the fils structure.
// All that's left is to write the IO side of things, some comments, and some tests!
// ===========================================================================================
//Come back, and finish writing the comments on everything that has a TODO
//Then we need to think of and write a system for encrypting a file into a new file.
//
//That should be portable to make it easy to write a file too.
//We'll worry about randomly accessing a file later on!
//
//Ooooh, maybe we have some kind of report metrics that can be run while it's going!
//That's actually a pretty cool idea and we should totally add that! Like, some running counter?
//
//1) Text people back
//
//2) Sand the poly board flatter
//3) Sand the poly shelves smoother
//4) Spray the next layer onto the poly shelves
//5) Paint the next layer onto the poly board
//6) Start painting the first layer onto the poly shield




// So, we read 4096 bytes from a file into a buffer,
// Then we break it up and encrypt it
// Then we run it through the summarizer
// Then we write it to our output file
// We continue doing that until we've reached the end of the file.
// then, we write the end marker, and seek to the beginning of the file to write in the header data.
// Yeah, we don't even need a ping-pong buffer!!





// TODO: open a file, and implement a ping-pong buffer, then run stuff over the buffers and into 


// So, now we get to work on my least favorite part... File IO stuff. Hooray.


// So, we want 3 things:
// 1) Take a file, and convert it to an ARH file
// 2) Take an ARH file and convert it to a file
// 3) Be able to open and randomly access an ARH file

pub fn encrypt_file(
    file_path: &str,
    master_encryption_key: &Key<Aes256>,
    signing_keys: ed25519_dalek::Keypair,
) {
    // Open the file we're going to encrypt.
    let Ok(mut input) = File::open(file_path) else { panic!("failed to open input"); };

    // Create a file to write the output into. It's the same as the input file, but with an extension of 'arh' on it.
    let mut output_path = PathBuf::from(file_path.to_owned() + ".arh");
    let Ok(mut output) = File::create(output_path) else { panic!("failed to open output"); };

    // Reserve space at the beginning of the file and seek to the contents portion of the file.
    let Ok(offset) = output.seek(SeekFrom::Start(constants::FILE_HEADER_SIZE)) else { panic!("failed to seek contents"); };
    if offset != constants::FILE_HEADER_SIZE { panic!("seek only went to: {offset}"); };



    // First, we derive a key that is specific to the provided data.
    // This ensures that even if an attacker manages to compromise this data or determine the key used to encrypt it,
    // all other data encrypted with the provided master key remains safe.
    //
    // derive a new file-specific key from the master encryption key, and initialize an AES engine with it.
    let derived_key_data::DerivedKeyData { derived_key, key_salt } = derived_key_data::DerivedKeyData::derive_new_from(master_encryption_key);
    let cipher = stream_cipher::StreamCipher::initialize(&derived_key.into());

    // Randomly generate a 128bit IV to initialize the AES-CTR engine with.
    let initial_value: u128 = rand::thread_rng().gen();

    // Create a summarizer for storing the length and hash of the input data.
    let mut summarizer = content_summarizer::ContentSummarizer::default();
    


    // Allocate a buffer we can read input data into.
    let mut buffer = [0_u8; 4096];

    // Read data from the input, encrypt it, and write it to the output.



    loop {
        // Try to read 4096 bytes from the file into the buffer.
        match input.read(&mut buffer) {
            Ok(len) => if len != 4096 { panic!("Only read {len} bytes!") }
            Err(err) => panic!("failed to read: {err:?}"),
        }
    }
}

/*
impl Aes256StreamCipher {
    pub fn encrypt_data(&self, data: &mut [u8], iv: u128) {
        let (blocks, remainder) = data.as_chunks_mut::<16>();

        blocks.into_par_iter().enumerate().for_each(|(i, block)| {
        })
    }
}
*/

pub fn encrypt_data<const L: usize>(
    data: &mut [u8],
    master_encryption_key: &[u8; 32],
) {
  //let cipher = Aes256StreamCipher::initialize(&derived_key);
  //cipher.encrypt_data(data, initial_value);
    
}

fn main() {
    println!("Hello, world!");
}


#![feature(file_create_new)]
#![feature(slice_as_chunks)]

// So, we want 3 things:
// 1) Take a file, and convert it to an ARH file                IMPLEMENTED
// 2) Take an ARH file and convert it to a file                 IMPLEMENTED
// 3) Be able to open and randomly access an ARH file

// ===== TODO ===== //
// Files that are still in progress: main, encryption, decryption.
// Add a license, README, cleanup the gitignore, and modify Cargo config file.
// Add some kind of progress callback to the main functions, so they can report how many bytes they've processed.
//
// See if using a ping-pong buffer for reading-processing input data improves performance.
// Add module comments to all the files.
// Maybe we should test `ReadResult::Error`?
// Should we be zeroing other things?

// Instead of taking files, maybe the encryption/decryption should just take Readers/Writers so we can have in-memory tests.

// TODO: go through and improve all the error messages to actually report useful information.

// TODO add a Read/Write wrapper for interacting with files programmatically that allows seeking and such.

// TODO add user interactivity (that can be undone with a command line flag).

// TODO ask the user if the file length is okay before decrypting a file!

// TODO stop assuming file extension exists, allow command line output option.
// Or if the extension is missing, we always prompt the user for an output path.

// TODO try to clean up files if encryption/decryption fails partway through?

// TODO refactor common logic into helper functions. For example: 'decrypt_file_checked' and 'decrypt_file_unchecked'
// are basically the same thing, we can probably simplify them without losing performance.

pub mod constants;
pub mod content_summarizer;
pub mod decryption_io;
pub mod encryption_io;
pub mod io_utils;
pub mod key_gen_utils;
pub mod signature_utils;
pub mod stream_cipher;

use crate::content_summarizer::ContentSummarizer;
use crate::decryption_io::{CipherFileReader, PlainFileWriter};
use crate::encryption_io::{CipherFileWriter, PlainFileReader};
use crate::key_gen_utils::DerivedKeyData;
use crate::stream_cipher::StreamCipher;
use std::collections::HashSet;
use std::io::{Error, ErrorKind, Result};
use std::path::{Path, PathBuf};
use aes::Aes256;
use cipher::Key;
use ed25519_dalek::{Keypair, PublicKey, Signature};
use io_utils::ReadResult;
use rand::Rng;
use rayon::prelude::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use zeroize::Zeroize;

pub struct Header {
    pub signature_key: [u8; 32],
    pub signature: [u8; 64],

    pub initial_counter_value: u128,
    pub encryption_key_salt: u64,

    pub content_length: u64,
}

/// TODO
pub fn verify_file(
    input_path: &(impl AsRef<Path> + ?Sized),
    trusted_public_keys: &HashSet<[u8; 32]>,
    expect_eof: bool,
) -> Result<()> {
    // Open the file we're going to verify.
    let mut input_file = CipherFileReader::open(input_path)?;

    // Ensure the public key that was used to sign the file is trusted by the user.
    let public_signing_key = PublicKey::from_bytes(&input_file.header().signature_key)
        .map_err(|error| Error::new(ErrorKind::Other, error))?;
    if !trusted_public_keys.contains(public_signing_key.as_bytes()) {
        return Err(Error::new(ErrorKind::Other, "File is signed with an untrusted key")); // TODO better message and functionality
    }

    // Create a summarizer to digest the inputted cipher text.
    let mut summarizer = ContentSummarizer::default();

    // Allocate a working buffer and counter.
    let mut buffer = [0_u8; 16384];
    let mut counter = 0;
    // Loop through the data in the input file.
    let expected_content_length = input_file.header().content_length;
    while counter < expected_content_length {
        // TODO
        let read_length = std::cmp::min((expected_content_length - counter) as usize, buffer.len());
        let read_buffer = &mut buffer[0..read_length];

        match input_file.try_read_from(read_buffer) {
            // TODO
            ReadResult::Full => {
                summarizer.update(read_buffer);
                counter += read_length as u64;
            }

            // TODO
            ReadResult::Eos(length) => {
                counter += length as u64;
                let message = format!("File header specified it contained {expected_content_length} bytes, but EOF was encountered after reading only {counter} bytes.");
                return Err(Error::new(ErrorKind::UnexpectedEof, message));
            }

            // If we encounter an unrecoverable error while reading, return it immediately.
            ReadResult::Error(error) => return Err(error),
        }
    }
    debug_assert_eq!(counter, expected_content_length);

    // Ensure that the file ends with a `FILE_END` marker, and that EOF is immediately after if `expect_eof` is true.
    input_file.check_file_end(expect_eof)?;

    // Compute a hash of the file's content.
    let (hash_value, content_length) = summarizer.finalize(
        input_file.header().initial_counter_value,
        input_file.header().encryption_key_salt,
    );
    debug_assert_eq!(content_length, expected_content_length);

    // TODO
    let signature = Signature::from_bytes(&input_file.header().signature)
        .map_err(|error| Error::new(ErrorKind::Other, error))?;
    if !signature_utils::verify_signature(&signature, &public_signing_key, &hash_value) {
        return Err(Error::new(ErrorKind::Other, "File signature does not match contents! File has been altered or corrupted.")) // TODO better message
    }

    Ok(())
}

/// TODO
pub fn encrypt_file(
    input_path: &(impl AsRef<Path> + ?Sized),
    master_encryption_key: &Key<Aes256>,
    signing_keys: &Keypair,
) -> Result<()> {
    // Open the file we're going to encrypt.
    let mut input_file = PlainFileReader::open(input_path)?;

    // Create a file to write the output into. It's the same as the input, but with ".arh" appended to it.
    let mut output_file_path = input_path.as_ref().to_owned();
    output_file_path.set_extension(
        input_path.as_ref()
            .extension()
            .map_or(
                PathBuf::from("arh"),
                |extension| {
                    let mut new_extension = extension.to_owned();
                    new_extension.push(".arh");
                    PathBuf::from(new_extension)
                },
            )
    );
    let mut output_file = CipherFileWriter::create_new(output_file_path)?;

    // Create an encryption key specific to this file, derived from the provided master key.
    // This ensures that even if an attacker manages to compromise this data or determine the key used to encrypt it,
    // all other data encrypted with the provided master key remains safe.
    let DerivedKeyData { mut derived_key, key_salt } = DerivedKeyData::derive_new_from(master_encryption_key);
    // Initialize a stream cipher with the derived key, then attempt to destroy it in memory.
    let cipher = StreamCipher::initialize(&derived_key);
    derived_key.zeroize();

    // Randomly generate a 128bit value to start the AES-CTR counter at.
    let initial_value = rand::thread_rng().gen();

    // Create a summarizer to digest the outputted cipher text.
    let mut summarizer = ContentSummarizer::default();

    // Allocate a working buffer and counter.
    let mut buffer = [0_u8; 16384];
    let mut counter = initial_value;
    // Loop through the data in the input file.
    loop {
        match input_file.try_read_from(&mut buffer) {
            // TODO
            ReadResult::Full => {
                let blocks = unsafe { buffer.as_chunks_unchecked_mut::<16>() };
                let block_counter_pairs = blocks.into_par_iter()
                    .enumerate()
                    .map(|(index, block)| (index as u128 + counter, block));

                cipher.process_blocks(block_counter_pairs);

                summarizer.update(&buffer);
                output_file.write_content(&buffer)?;

                counter += buffer.len() as u128;
            }

            // TODO
            ReadResult::Eos(length) => {
                let filled_buffer = &mut buffer[0..length];

                let (blocks, remainder) = filled_buffer.as_chunks_mut::<16>();
                let block_counter_pairs = blocks.into_par_iter()
                    .enumerate()
                    .map(|(index, block)| (index as u128 + counter, block));

                cipher.process_blocks(block_counter_pairs);
                cipher.process_block(blocks.len() as u128 + counter, remainder);

                summarizer.update(filled_buffer);
                output_file.write_content(filled_buffer)?;

                counter += length as u128;
                break;
            }

            // If we encounter an unrecoverable error while reading, return it immediately.
            ReadResult::Error(error) => return Err(error),
        }
    }
    // Hitting this point means we've finished writing the contents of the encrypted output file.

    // Compute a hash for the file's contents and sign it with the provided key pair.
    let (hash_value, content_length) = summarizer.finalize(initial_value, key_salt);
    let signed_hash_value = signature_utils::sign_message(&hash_value, signing_keys);

    // Finalize the file by writing an ARH header and footer around the contents we've finished writing.
    let header = Header {
        signature_key: signing_keys.public.to_bytes(),
        signature: signed_hash_value.to_bytes(),
        initial_counter_value: initial_value,
        encryption_key_salt: key_salt,
        content_length,
    };
    output_file.finalize(&header)
}

pub fn decrypt_file_checked(
    input_path: &(impl AsRef<Path> + ?Sized),
    master_encryption_key: &Key<Aes256>,
    trusted_public_keys: &HashSet<[u8; 32]>,
    expect_eof: bool,
) -> Result<()> {
    // Open the input file we're going to decrypt.
    let mut input_file = CipherFileReader::open(input_path)?;

    // Ensure the public key that was used to sign the file is trusted by the user.
    let public_signing_key = PublicKey::from_bytes(&input_file.header().signature_key)
        .map_err(|error| Error::new(ErrorKind::Other, error))?;
    if !trusted_public_keys.contains(public_signing_key.as_bytes()) {
        return Err(Error::new(ErrorKind::Other, "File is signed with an untrusted key")); // TODO better message and functionality
    }

    // Create a file to write the output into. It's the same as the input, but without a trailing ".arh" extension.
    let mut output_file_path = input_path.as_ref().to_owned();
    output_file_path.set_extension(
        input_path.as_ref()
            .extension()
            .map_or(
                PathBuf::from("dec"),
                |extension| {
                    // TODO MAKE THIS THE REAL FILE NAME!
                    let mut new_extension = extension.to_owned();
                    new_extension.push(".dec");
                    PathBuf::from(new_extension)
                },
            )
    );
    let mut output_file = PlainFileWriter::create_new(output_file_path)?;

    // Compute the encryption key used by this file with the provided master key and salt value in this file's header.
    let mut derived_key = DerivedKeyData::re_derive_from(master_encryption_key, input_file.header().encryption_key_salt);
    // Initialize a stream cipher with the derived key, then attempt to destroy it in memory.
    let cipher = StreamCipher::initialize(&derived_key);
    derived_key.zeroize();

    // Load the initial value to start the AES-CTR counter at.
    let initial_value = input_file.header().initial_counter_value;

    // Create a summarizer to digest the inputted cipher text.
    let mut summarizer = ContentSummarizer::default();

    // Allocate a working buffer and counters.
    let mut buffer = [0_u8; 16384];
    let mut counter = 0;
    // Loop through the data in the input file.
    let expected_content_length = input_file.header().content_length;
    while counter < expected_content_length {
        // TODO
        let read_length = std::cmp::min((expected_content_length - counter) as usize, buffer.len());
        let read_buffer = &mut buffer[0..read_length];

        match input_file.try_read_from(read_buffer) {
            // TODO
            ReadResult::Full => {
                summarizer.update(read_buffer);

                let (blocks, remainder) = read_buffer.as_chunks_mut::<16>();
                let block_counter_pairs = blocks.into_par_iter()
                    .enumerate()
                    .map(|(index, block)| (initial_value + (index as u128) + (counter as u128), block));

                cipher.process_blocks(block_counter_pairs);
                cipher.process_block(initial_value + (blocks.len() as u128) + (counter as u128), remainder);

                output_file.write_content(read_buffer)?;
                counter += read_length as u64;
            }

            // TODO
            ReadResult::Eos(length) => {
                counter += length as u64;
                let message = format!("File header specified it contained {expected_content_length} bytes, but EOF was encountered after reading only {counter} bytes.");
                return Err(Error::new(ErrorKind::UnexpectedEof, message));
            }

            // If we encounter an unrecoverable error while reading, return it immediately.
            ReadResult::Error(error) => return Err(error),
        }
    }
    debug_assert_eq!(counter, expected_content_length);

    // Ensure that the file ends with a `FILE_END` marker, and that EOF is immediately after if `expect_eof` is true.
    input_file.check_file_end(expect_eof)?;

    // Compute a hash of the file's content.
    let (hash_value, content_length) = summarizer.finalize(
        input_file.header().initial_counter_value,
        input_file.header().encryption_key_salt,
    );
    debug_assert_eq!(content_length, expected_content_length);

    // TODO
    let signature = Signature::from_bytes(&input_file.header().signature)
        .map_err(|error| Error::new(ErrorKind::Other, error))?;
    if !signature_utils::verify_signature(&signature, &public_signing_key, &hash_value) {
        return Err(Error::new(ErrorKind::Other, "File signature does not match contents! File has been altered or corrupted.")) // TODO better message
    }

    Ok(())
}

pub fn decrypt_file_unchecked(
    input_path: &(impl AsRef<Path> + ?Sized),
    master_encryption_key: &Key<Aes256>,
    expect_eof: bool,
) -> Result<()> {
    // Open the input file we're going to decrypt.
    let mut input_file = CipherFileReader::open(input_path)?;

    // Create a file to write the output into. It's the same as the input, but without a trailing ".arh" extension.
    let mut output_file_path = input_path.as_ref().to_owned();
    output_file_path.set_extension(
        input_path.as_ref()
            .extension()
            .map_or(
                PathBuf::from("dec"),
                |extension| {
                    // TODO MAKE THIS THE REAL FILE NAME!
                    let mut new_extension = extension.to_owned();
                    new_extension.push(".dec");
                    PathBuf::from(new_extension)
                },
            )
    );
    let mut output_file = PlainFileWriter::create_new(output_file_path)?;

    // Compute the encryption key used by this file with the provided master key and salt value in this file's header.
    let mut derived_key = DerivedKeyData::re_derive_from(master_encryption_key, input_file.header().encryption_key_salt);
    // Initialize a stream cipher with the derived key, then attempt to destroy it in memory.
    let cipher = StreamCipher::initialize(&derived_key);
    derived_key.zeroize();

    // Load the initial value to start the AES-CTR counter at.
    let initial_value = input_file.header().initial_counter_value;

    // Allocate a working buffer and counters.
    let mut buffer = [0_u8; 16384];
    let mut counter = 0;
    // Loop through the data in the input file.
    let expected_content_length = input_file.header().content_length;
    while counter < expected_content_length {
        // TODO
        let read_length = std::cmp::min((expected_content_length - counter) as usize, buffer.len());
        let read_buffer = &mut buffer[0..read_length];

        match input_file.try_read_from(read_buffer) {
            // TODO
            ReadResult::Full => {
                let (blocks, remainder) = read_buffer.as_chunks_mut::<16>();
                let block_counter_pairs = blocks.into_par_iter()
                    .enumerate()
                    .map(|(index, block)| (initial_value + (index as u128) + (counter as u128), block));

                cipher.process_blocks(block_counter_pairs);
                cipher.process_block(initial_value + (blocks.len() as u128) + (counter as u128), remainder);

                output_file.write_content(read_buffer)?;
                counter += read_length as u64;
            }

            // TODO
            ReadResult::Eos(length) => {
                counter += length as u64;
                let message = format!("File header specified it contained {expected_content_length} bytes, but EOF was encountered after reading only {counter} bytes.");
                return Err(Error::new(ErrorKind::UnexpectedEof, message));
            }

            // If we encounter an unrecoverable error while reading, return it immediately.
            ReadResult::Error(error) => return Err(error),
        }
    }
    debug_assert_eq!(counter, expected_content_length);

    // Ensure that the file ends with a `FILE_END` marker, and that EOF is immediately after if `expect_eof` is true.
    input_file.check_file_end(expect_eof)?;

    Ok(())
}



fn main() {
    let signing_keys = key_gen_utils::generate_new_signing_keys();
    let master_encryption_key = key_gen_utils::generate_new_encryption_key();
    match encrypt_file("/Users/austin/archive-fs/test.txt", &master_encryption_key, &signing_keys) {
        Ok(_) => println!("Finished encrypting Successfully!"),
        Err(err) => {
            println!("Writing Error: {err:?}");
            return;
        }
    }

    let mut trusted_public_keys = HashSet::new();
    trusted_public_keys.insert(signing_keys.public.to_bytes());

    match verify_file("/Users/austin/archive-fs/test.txt.arh", &trusted_public_keys, true) {
        Ok(_) => println!("Finished verifying Successfully!"),
        Err(err) => {
            println!("Verification Error: {err:?}");
            return;
        }
    }

    match decrypt_file_checked("/Users/austin/archive-fs/test.txt.arh", &master_encryption_key, &trusted_public_keys, true) {
        Ok(_) => println!("Finished decrypting Successfully!"),
        Err(err) => {
            println!("Decryption Error: {err:?}");
            return;
        }
    }

    println!("COMPLETED!");
}

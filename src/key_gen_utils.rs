
use aes::Aes256;
use cipher::Key;
use ed25519_dalek::Keypair;
use rand::Rng;
use rand_old::rngs::OsRng;

/// Generate a new 256bit AES encryption key from the OS's randomness source.
pub fn generate_new_encryption_key() -> Key<Aes256> {
    // Randomly generate an array of 32 bytes, then convert it into a 256bit key value.
    rand::thread_rng().gen::<[u8; 32]>().into()
}

/// Generate a new pair of 256bit EdDSA keys from the OS's randomness source.
pub fn generate_new_signing_keys() -> Keypair {
    Keypair::generate(&mut OsRng {})
}

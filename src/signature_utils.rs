
use ed25519_dalek::{ExpandedSecretKey, Keypair, Signature, PublicKey};

/// TODO
pub fn sign_message(message: &[u8], signing_keys: &Keypair) -> Signature {
    let expanded_key = ExpandedSecretKey::from(&signing_keys.secret);
    expanded_key.sign(message, &signing_keys.public)
}

/// TODO
pub fn verify_signature(signature: &Signature, public_key: PublicKey, expected: &[u8]) -> bool {
    public_key.verify_strict(expected, signature).is_ok()
}

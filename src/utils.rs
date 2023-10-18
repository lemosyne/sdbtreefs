use super::Key;
use rand::{CryptoRng, RngCore};

pub fn generate_key<R, const KEY_SZ: usize>(rng: &mut R) -> Key<KEY_SZ>
where
    R: RngCore + CryptoRng,
{
    let mut key = [0; KEY_SZ];
    rng.fill_bytes(&mut key);
    key
}

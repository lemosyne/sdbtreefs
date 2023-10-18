use super::Key;
use crypter::Crypter;
use kms::KeyManagementScheme;
use rand::{CryptoRng, RngCore};
use sdbtree::{error::Error, storage::Storage, BKeyTree};

pub struct LocalizedBKeyTree<'a, R, S, C, const KEY_SZ: usize>
where
    R: RngCore + CryptoRng,
    S: Storage<Id = u64>,
    C: Crypter,
{
    id: u64,
    inner: &'a mut BKeyTree<R, S, C, KEY_SZ>,
}

impl<'a, R, S, C, const KEY_SZ: usize> LocalizedBKeyTree<'a, R, S, C, KEY_SZ>
where
    R: RngCore + CryptoRng,
    S: Storage<Id = u64>,
    C: Crypter,
{
    pub fn new(id: u64, inner: &'a mut BKeyTree<R, S, C, KEY_SZ>) -> Self {
        Self { id, inner }
    }

    fn localize(&self, block: u64) -> u64 {
        self.id << 32 | block
    }
}

impl<'a, R, S, C, const KEY_SZ: usize> KeyManagementScheme
    for LocalizedBKeyTree<'a, R, S, C, KEY_SZ>
where
    R: RngCore + CryptoRng + Default,
    S: Storage<Id = u64>,
    C: Crypter,
{
    type Key = Key<KEY_SZ>;
    type KeyId = u64;
    type Error = Error<S::Error>;

    fn derive(&mut self, block: Self::KeyId) -> Result<Self::Key, Self::Error> {
        self.inner.derive(self.localize(block))
    }

    fn update(&mut self, block: Self::KeyId) -> Result<Self::Key, Self::Error> {
        self.inner.update(self.localize(block))
    }

    fn commit(&mut self) -> Vec<Self::KeyId> {
        self.inner.commit()
    }
}

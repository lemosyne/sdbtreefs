use crate::{error::Error, SDBResult, SDBTreeFs};
use allocator::Allocator;
use crypter::Crypter;
use embedded_io::{
    adapters::FromStd,
    blocking::{Read, Seek, Write},
    SeekFrom,
};
use rand::{CryptoRng, RngCore};
use sdbtree::storage::Storage;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fs::File;

impl<A, R, S, C, const KEY_SZ: usize, const BLOCK_SZ: usize> SDBTreeFs<A, R, S, C, KEY_SZ, BLOCK_SZ>
where
    for<'de> A: Allocator<Id = u64> + Default + Serialize + Deserialize<'de> + 'static,
    R: RngCore + CryptoRng + Default + 'static,
    S: Storage<Id = u64> + 'static,
    C: Crypter + 'static,
{
    pub(crate) fn allocator_path(&self) -> String {
        format!("{}/allocator", self.metadir)
    }

    pub(crate) fn links_path(&self) -> String {
        format!("{}/links", self.metadir)
    }

    pub(crate) fn mappings_path(&self) -> String {
        format!("{}/mappings", self.metadir)
    }

    pub(crate) fn root_path(&self) -> String {
        format!("{}/root", self.metadir)
    }

    pub fn is_loadable(&mut self) -> SDBResult<bool> {
        // If a key is in the enclave, we should have persisted state that we can load.
        self.enclave.seek(SeekFrom::End(0))?;
        Ok(self.enclave.stream_position()? != 0)
    }

    pub fn load(&mut self) -> SDBResult<()> {
        // Load the root key from the enclave.
        let mut root_key = [0; KEY_SZ];
        self.enclave.seek(SeekFrom::Start(0))?;
        self.enclave
            .read_exact(&mut root_key)
            .map_err(|_| Error::Enclave)?;

        // Load the public state: links, mappings, allocator, and root ID.
        let links = Self::load_serializable(&self.links_path())?;
        let mappings = Self::load_serializable(&self.mappings_path())?;
        let allocator = Self::load_serializable(&self.allocator_path())?;
        let root_id = Self::load_serializable(&self.root_path())?;

        // Load the BTree.
        self.tree
            .load(root_id, root_key)
            .map_err(|_| Error::Storage)?;

        // We can go ahead and update the rest of the state.
        self.links = links;
        self.mappings = mappings;
        self.allocator = allocator;
        self.root_id = root_id;
        self.root_key = self.root_key;

        Ok(())
    }

    pub fn persist(&mut self) -> SDBResult<()> {
        // Persist the BTree, which will give us the next root ID and root key.
        (self.root_id, self.root_key) = self.tree.persist().map_err(|_| Error::Storage)?;

        // Persist the public state: links, mappings, allocator, and root ID.
        Self::persist_serializable(&self.links_path(), &self.links)?;
        Self::persist_serializable(&self.mappings_path(), &self.mappings)?;
        Self::persist_serializable(&self.allocator_path(), &self.allocator)?;
        Self::persist_serializable(&self.root_path(), &self.root_id)?;

        // Persist the root key to the enclave.
        self.enclave.seek(SeekFrom::Start(0))?;
        self.enclave.write_all(&self.root_key)?;

        Ok(())
    }

    fn load_serializable<T: DeserializeOwned>(path: &str) -> SDBResult<T> {
        let mut ser = vec![];

        let mut reader = Self::new_read_io(path)?;
        reader.read_to_end(&mut ser)?;

        Ok(bincode::deserialize(&ser)?)
    }

    fn persist_serializable(path: &str, object: &impl Serialize) -> SDBResult<()> {
        let ser = bincode::serialize(object)?;

        let mut writer = Self::new_write_io(path)?;
        writer.write_all(&ser)?;

        Ok(())
    }

    pub fn new_read_io(path: &str) -> SDBResult<FromStd<File>> {
        Ok(FromStd::new(File::options().read(true).open(path)?))
    }

    pub fn new_write_io(path: &str) -> SDBResult<FromStd<File>> {
        Ok(FromStd::new(
            File::options()
                .read(true)
                .write(true)
                .create(true)
                .open(path)?,
        ))
    }
}

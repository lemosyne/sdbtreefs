pub mod error;
mod localize;
pub mod persist;
pub mod utils;

use allocator::{seq::SequentialAllocator, Allocator};
use anyhow::{anyhow, Result};
use core::ffi::*;
use crypter::{openssl::Aes256Ctr, Crypter};
use cryptio::iv::BlockIvCryptIo;
use embedded_io::adapters::FromStd;
use embedded_io::{
    blocking::{Read, Seek, Write},
    SeekFrom,
};
use error::{Error, Result as SDBResult};
use fuse_sys::*;
use localize::LocalizedBKeyTree;
use log::*;
use passthrough::Passthrough;
use rand::{rngs::ThreadRng, CryptoRng, RngCore};
use sdbtree::{
    storage::{dir::DirectoryStorage, Storage},
    BKeyTree,
};
use serde::{Deserialize, Serialize};
use std::env;
use std::marker::PhantomData;
use std::{collections::HashMap, fs::File};
use umask::Mode;

const AES256CTR_KEY_SZ: usize = 32;
const DEFAULT_BLOCK_SIZE: usize = 4096;
const DEFAULT_DEGREE: usize = 2;
type Key<const N: usize> = [u8; N];

pub struct SDBTreeFs<
    A = SequentialAllocator<u64>,
    R = ThreadRng,
    S = DirectoryStorage,
    C = Aes256Ctr,
    const KEY_SZ: usize = AES256CTR_KEY_SZ,
    const BLOCK_SZ: usize = DEFAULT_BLOCK_SIZE,
> where
    for<'de> A: Allocator<Id = u64> + Default + Serialize + Deserialize<'de>,
    R: RngCore + CryptoRng + Default,
    S: Storage<Id = u64>,
    C: Crypter,
{
    root_id: u64,
    root_key: Key<KEY_SZ>,
    tree: BKeyTree<R, S, C, KEY_SZ>,
    enclave: FromStd<File>,
    metadir: String,
    mappings: HashMap<String, u64>,
    links: HashMap<u64, u64>,
    inner: Passthrough,
    allocator: A,
}

impl SDBTreeFs {
    pub fn new(
        enclave: impl AsRef<str>,
        datadir: impl AsRef<str>,
        metadir: impl AsRef<str>,
    ) -> SDBResult<Self> {
        Self::custom(
            enclave,
            datadir,
            metadir.as_ref(),
            DirectoryStorage::new(metadir.as_ref()).map_err(|_| Error::Storage)?,
        )
    }

    pub fn options() -> SDBTreeFsBuilder<
        SequentialAllocator<u64>,
        ThreadRng,
        DirectoryStorage,
        Aes256Ctr,
        AES256CTR_KEY_SZ,
        DEFAULT_BLOCK_SIZE,
    > {
        Self::custom_options()
    }
}

impl<A, R, S, C, const KEY_SZ: usize, const BLOCK_SZ: usize> SDBTreeFs<A, R, S, C, KEY_SZ, BLOCK_SZ>
where
    for<'de> A: Allocator<Id = u64> + Default + Serialize + Deserialize<'de> + 'static,
    R: RngCore + CryptoRng + Default + 'static,
    S: Storage<Id = u64> + 'static,
    C: Crypter + 'static,
{
    pub fn custom(
        enclave: impl AsRef<str>,
        datadir: impl AsRef<str>,
        metadir: impl AsRef<str>,
        storage: S,
    ) -> SDBResult<Self> {
        Ok(Self::custom_options().build(enclave, datadir, metadir, storage)?)
    }

    pub fn custom_options() -> SDBTreeFsBuilder<A, R, S, C, KEY_SZ, BLOCK_SZ> {
        SDBTreeFsBuilder::new()
    }

    pub fn mount(mut self, mount: impl AsRef<str>) -> Result<()> {
        // Before we mount, we can try to load state.
        if self.is_loadable()? {
            self.load()?;
        }

        let exec = env::args().next().unwrap().to_string();

        let mut args = vec![exec.as_str(), mount.as_ref()];
        if self.inner.is_debug() {
            args.push("-d");
        }
        if self.inner.is_foreground() {
            args.push("-f");
        }

        self.run(&args)
            .map_err(|err| anyhow!("unexpected FUSE error: {err}"))
    }

    fn canonicalize(&self, path: &str) -> String {
        self.inner.canonicalize(path).to_string_lossy().to_string()
    }

    fn localize(id: u64, block: u64) -> u64 {
        id << 20 | (block & ((1 << 20) - 1))
    }
}

impl<A, R, S, C, const KEY_SZ: usize, const BLOCK_SZ: usize> UnthreadedFileSystem
    for SDBTreeFs<A, R, S, C, KEY_SZ, BLOCK_SZ>
where
    for<'de> A: Allocator<Id = u64> + Default + Serialize + Deserialize<'de> + 'static,
    R: RngCore + CryptoRng + Default + 'static,
    S: Storage<Id = u64> + 'static,
    C: Crypter + 'static,
{
    fn getattr(
        &mut self,
        path: &str,
        mut stbuf: Option<&mut fuse_sys::stat>,
        fi: Option<&mut fuse_sys::fuse_file_info>,
    ) -> Result<i32> {
        let raw: *mut stat = *stbuf.as_mut().unwrap() as *mut _;
        let res = self.inner.getattr(path, stbuf, fi)?;

        // Need to fix the size of the file due to the padding caused by IVs.
        if res == 0 {
            let mode = unsafe { (*raw).st_mode };
            let raw_size = unsafe { (*raw).st_size };
            if mode & libc::S_IFMT == libc::S_IFREG {
                let padded_block_size = (BLOCK_SZ + C::iv_length()) as i64;
                let padded_blocks = (raw_size + padded_block_size - 1) / padded_block_size;
                let iv_size = padded_blocks * C::iv_length() as i64;
                let size = raw_size - iv_size;
                debug!("getattr: path = {path}, res = {res}, size = {size}");
                unsafe {
                    (*raw).st_size = size;
                }
            } else {
                debug!("getattr: path = {path}, res = {res}, size = {raw_size}");
            }
        }

        Ok(res)
    }

    fn readlink(&mut self, path: &str, buf: &mut [u8]) -> Result<i32> {
        debug!("readlink: path = {path}");
        self.inner.readlink(path, buf)
    }

    fn mkdir(&mut self, path: &str, mode: mode_t) -> Result<i32> {
        debug!("mkdir: path = {path}, mode = {}", Mode::from(mode | 0o666));
        self.inner.mkdir(path, mode | 0o666)
    }

    fn unlink(&mut self, path: &str) -> Result<i32> {
        debug!("unlink: path = {path}");

        let res = self.inner.unlink(path)?;
        if res == 0 {
            let id = self
                .mappings
                .remove(&self.canonicalize(path))
                .ok_or(Error::Mapping(self.canonicalize(path)))?;
            let links = self.links.entry(id).or_insert(1);

            *links -= 1;

            if *links == 0 {
                self.allocator.dealloc(id).map_err(|_| Error::Dealloc(id))?;

                // This is super jank, but we'll just try to remove all the keys.
                for block in 0.. {
                    if self
                        .tree
                        .remove(&Self::localize(id, block))
                        .map_err(|_| Error::Storage)?
                        .is_none()
                    {
                        break;
                    }
                }
            }
        }

        Ok(res)
    }

    fn rmdir(&mut self, path: &str) -> Result<i32> {
        debug!("rmdir: path = {path}");
        self.inner.rmdir(path)
    }

    fn symlink(&mut self, from: &str, to: &str) -> Result<i32> {
        debug!("symlink: from = {from}, to = {to}");

        let res = self.inner.symlink(from, to)?;
        if res == 0 {
            let from_ipath = self.canonicalize(from);
            let to_ipath = self.canonicalize(to);

            let id = *self
                .mappings
                .get(&from_ipath)
                .ok_or(Error::Mapping(from_ipath))?;

            self.mappings.insert(to_ipath, id);
            *self.links.entry(id).or_insert(0) += 1;
        }

        Ok(res)
    }

    fn rename(&mut self, from: &str, to: &str, flags: c_uint) -> Result<i32> {
        debug!("rename: from = {from}, to = {to}");

        let res = self.inner.rename(from, to, flags)?;
        if res == 0 {
            let from_ipath = self.canonicalize(from);
            let to_ipath = self.canonicalize(to);

            let id = self
                .mappings
                .remove(&from_ipath)
                .ok_or(Error::Mapping(from_ipath))?;

            self.mappings.insert(to_ipath, id);
        }

        Ok(res)
    }

    fn link(&mut self, from: &str, to: &str) -> Result<i32> {
        debug!("link: from = {from}, to = {to}");

        let res = self.inner.link(from, to)?;
        if res == 0 {
            let from_ipath = self.canonicalize(from);
            let to_ipath = self.canonicalize(to);

            let id = *self
                .mappings
                .get(&from_ipath)
                .ok_or(Error::Mapping(from_ipath))?;

            self.mappings.insert(to_ipath, id);
            *self.links.entry(id).or_insert(0) += 1;
        }

        Ok(res)
    }

    fn chmod(&mut self, path: &str, mode: mode_t, fi: Option<&mut fuse_file_info>) -> Result<i32> {
        debug!("chmod: path = {path}, mode = {}", Mode::from(mode | 0o666));
        self.inner.chmod(path, mode | 0o666, fi)
    }

    fn chown(
        &mut self,
        path: &str,
        uid: uid_t,
        gid: gid_t,
        fi: Option<&mut fuse_file_info>,
    ) -> Result<i32> {
        debug!("chown: path = {path}, uid = {uid}, gid = {gid}");
        self.inner.chown(path, uid, gid, fi)
    }

    // fn truncate(
    //     &mut self,
    //     path: &str,
    //     size: off_t,
    //     fi: Option<&mut fuse_file_info>,
    // ) -> Result<i32> {
    //     debug!("truncate: path = {path}, size = {size}");

    //     let size = size as u64;
    //     let ipath = self.inode_path(path);

    //     let khf_id = *self
    //         .mappings
    //         .get(&ipath)
    //         .ok_or(Error::MissingKhf(ipath.clone()))?;

    //     // Number of bytes past a block.
    //     let extra = size % BLOCK_SZ as u64;

    //     // Need to rewrite the extra bytes.
    //     if extra > 0 {
    //         let mut io = self.new_rw_io(&ipath)?;
    //         let mut buf = vec![0; extra as usize];
    //         let offset = (size / BLOCK_SZ as u64) * BLOCK_SZ as u64;

    //         // Read in the extra bytes.
    //         io.seek(SeekFrom::Start(offset))?;
    //         io.read(&mut buf)?;

    //         // Write the extra bytes.
    //         io.seek(SeekFrom::Start(offset))?;
    //         io.write(&buf)?;
    //     }

    //     // Truncate the forest Not needed for security, but nice for efficiency.
    //     let keys = (size + (BLOCK_SZ as u64 - 1)) / BLOCK_SZ as u64;
    //     self.get_mut_inode_khf(&ipath)?
    //         .ok_or(Error::MissingKhf(ipath))?
    //         .truncate(keys);

    //     // Update the `Khf` and truncate the inode.
    //     self.master_khf.update(khf_id)?;
    //     self.inner.truncate(path, size as i64, fi)
    // }

    fn open(&mut self, path: &str, fi: Option<&mut fuse_file_info>) -> Result<i32> {
        debug!("open: path = {path}");
        self.inner.open(path, fi)
    }

    fn read(
        &mut self,
        path: &str,
        buf: &mut [u8],
        offset: off_t,
        _fi: Option<&mut fuse_file_info>,
    ) -> Result<i32> {
        debug!("read: path = {path}");

        let ipath = self.canonicalize(path);
        let io = Self::new_read_io(&ipath)?;
        let id = self.mappings.get(&ipath).ok_or(Error::Mapping(ipath))?;

        let mut tree = LocalizedBKeyTree::new(*id, Self::localize, &mut self.tree);
        let mut reader = BlockIvCryptIo::<
            _,
            LocalizedBKeyTree<'_, R, S, C, KEY_SZ>,
            R,
            C,
            BLOCK_SZ,
            KEY_SZ,
        >::new(io, &mut tree, R::default());

        reader.seek(SeekFrom::Start(offset as u64))?;
        Ok(reader.read(buf)? as i32)
    }

    fn write(
        &mut self,
        path: &str,
        buf: &[u8],
        offset: off_t,
        _fi: Option<&mut fuse_file_info>,
    ) -> Result<i32> {
        debug!(
            "write: path = {path}, offset = {}, size = {}",
            offset,
            buf.len()
        );

        let ipath = self.canonicalize(path);
        let io = Self::new_write_io(&ipath)?;
        let id = self.mappings.get(&ipath).ok_or(Error::Mapping(ipath))?;

        let mut tree = LocalizedBKeyTree::new(*id, Self::localize, &mut self.tree);
        let mut writer = BlockIvCryptIo::<
            _,
            LocalizedBKeyTree<'_, R, S, C, KEY_SZ>,
            R,
            C,
            BLOCK_SZ,
            KEY_SZ,
        >::new(io, &mut tree, R::default());

        writer.seek(SeekFrom::Start(offset as u64))?;
        Ok(writer.write(buf)? as i32)
    }

    fn statfs(&mut self, path: &str, stbuf: Option<&mut statvfs>) -> Result<i32> {
        debug!("statfs: path = {path}");
        self.inner.statfs(path, stbuf)
    }

    fn flush(&mut self, path: &str, fi: Option<&mut fuse_file_info>) -> Result<i32> {
        debug!("flush: path = {path}");
        self.inner.flush(path, fi)
    }

    fn release(&mut self, path: &str, fi: Option<&mut fuse_file_info>) -> Result<i32> {
        debug!("release: path = {path}");
        self.inner.release(path, fi)
    }

    fn fsync(
        &mut self,
        path: &str,
        isdatasync: c_int,
        fi: Option<&mut fuse_file_info>,
    ) -> Result<i32> {
        debug!("fsync: path = {path}");
        let res = self.inner.fsync(path, isdatasync, fi)?;
        if res == 0 {
            let ipath = self.canonicalize(path);
            let id = self.mappings.get(&ipath).ok_or(Error::Mapping(ipath))?;

            // This is super jank, but we just need to find and persist the nodes containing the
            // block keys for the inode.
            for block in 0.. {
                if !self
                    .tree
                    .persist_block(&Self::localize(*id, block))
                    .map_err(|_| Error::Storage)?
                {
                    break;
                }
            }
        }
        Ok(res)
    }

    fn opendir(&mut self, path: &str, fi: Option<&mut fuse_file_info>) -> Result<i32> {
        debug!("opendir: path = {path}");
        self.inner.opendir(path, fi)
    }

    fn readdir(
        &mut self,
        path: &str,
        buf: Option<&mut c_void>,
        filler: fuse_fill_dir_t,
        offset: off_t,
        fi: Option<&mut fuse_file_info>,
        flags: fuse_readdir_flags,
    ) -> Result<i32> {
        debug!("readdir: path = {path}");
        self.inner.readdir(path, buf, filler, offset, fi, flags)
    }

    fn releasedir(&mut self, path: &str, fi: Option<&mut fuse_file_info>) -> Result<i32> {
        debug!("releasedir: path = {path}");
        self.inner.releasedir(path, fi)
    }

    fn access(&mut self, path: &str, mask: c_int) -> Result<i32> {
        debug!("access: path = {path}");
        self.inner.access(path, mask)
    }

    fn create(&mut self, path: &str, mode: mode_t, fi: Option<&mut fuse_file_info>) -> Result<i32> {
        debug!("create: path = {path}, mode = {}", Mode::from(mode | 0o666));

        let res = self.inner.create(path, mode | 0o666, fi)?;

        let ipath = self.canonicalize(path);
        let id = self.allocator.alloc().map_err(|_| Error::Alloc)?;

        self.mappings.insert(ipath, id);
        *self.links.entry(id).or_insert(0) += 1;

        Ok(res)
    }

    // NOTE: Doesn't need to be implemented.
    // fn write_buf(
    //     &mut self,
    //     path: &str,
    //     buf: Option<&mut fuse_bufvec>,
    //     offset: off_t,
    //     fi: Option<&mut fuse_file_info>,
    // ) -> Result<i32> {
    //     self.inner.write_buf(path, buf, offset, fi)
    // }

    // NOTE: Doesn't need to be implemented.
    // fn read_buf(
    //     &mut self,
    //     path: &str,
    //     bufp: &mut [&mut fuse_bufvec],
    //     offset: off_t,
    //     fi: Option<&mut fuse_file_info>,
    // ) -> Result<i32> {
    //     self.inner.read_buf(path, bufp, offset, fi)
    // }

    fn flock(&mut self, path: &str, fi: Option<&mut fuse_file_info>, op: c_int) -> Result<i32> {
        debug!("flock: path = {path}");
        self.inner.flock(path, fi, op)
    }

    fn lock(
        &mut self,
        path: &str,
        fi: Option<&mut fuse_file_info>,
        cmd: c_int,
        lock: Option<&mut flock>,
    ) -> Result<i32> {
        debug!("lock: path = {path}");
        self.inner.lock(path, fi, cmd, lock)
    }
}

pub struct SDBTreeFsBuilder<A, R, S, C, const KEY_SZ: usize, const BLOCK_SZ: usize>
where
    for<'de> A: Allocator<Id = u64> + Default + Serialize + Deserialize<'de>,
    R: RngCore + CryptoRng + Default,
    S: Storage<Id = u64>,
    C: Crypter,
{
    debug: bool,
    foreground: bool,
    degree: usize,
    pd: PhantomData<(A, R, S, C)>,
}

impl<A, R, S, C, const KEY_SZ: usize, const BLOCK_SZ: usize>
    SDBTreeFsBuilder<A, R, S, C, KEY_SZ, BLOCK_SZ>
where
    for<'de> A: Allocator<Id = u64> + Default + Serialize + Deserialize<'de>,
    R: RngCore + CryptoRng + Default,
    S: Storage<Id = u64>,
    C: Crypter,
{
    pub fn new() -> Self {
        Self {
            debug: true,
            foreground: true,
            degree: DEFAULT_DEGREE,
            pd: PhantomData,
        }
    }

    pub fn debug(mut self, debug: bool) -> Self {
        self.debug = debug;
        self
    }

    pub fn foreground(mut self, foreground: bool) -> Self {
        self.foreground = foreground;
        self
    }

    pub fn degree(mut self, degree: usize) -> Self {
        self.degree = degree;
        self
    }

    pub fn build(
        self,
        enclave: impl AsRef<str>,
        datadir: impl AsRef<str>,
        metadir: impl AsRef<str>,
        storage: S,
    ) -> SDBResult<SDBTreeFs<A, R, S, C, KEY_SZ, BLOCK_SZ>> {
        let root_key = utils::generate_key(&mut R::default());

        Ok(SDBTreeFs {
            root_id: 0,
            root_key,
            tree: BKeyTree::with_storage(storage, root_key).map_err(|_| Error::Storage)?,
            enclave: FromStd::new(
                File::options()
                    .read(true)
                    .write(true)
                    .create(true)
                    .open(enclave.as_ref())?,
            ),
            metadir: metadir.as_ref().into(),
            mappings: HashMap::new(),
            links: HashMap::new(),
            inner: Passthrough::options()
                .debug(self.debug)
                .foreground(self.foreground)
                .build::<&str>(datadir.as_ref().into()),
            allocator: A::default(),
        })
    }
}

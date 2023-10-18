pub mod error;
mod localize;
pub mod utils;

use anyhow::Result;
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
use log::*;
use passthrough::Passthrough;
use rand::{rngs::ThreadRng, CryptoRng, RngCore};
use sdbtree::{
    storage::{dir::DirectoryStorage, Storage},
    BKeyTree,
};
use std::{collections::HashMap, fs::File};
use umask::Mode;

use crate::localize::LocalizedBKeyTree;

const AES256CTR_KEY_SZ: usize = 32;
const DEFAULT_BLOCK_SIZE: usize = 4096;
type Key<const N: usize> = [u8; N];

pub struct SDBTreeFs<
    R = ThreadRng,
    S = DirectoryStorage,
    C = Aes256Ctr,
    const KEY_SZ: usize = AES256CTR_KEY_SZ,
    const BLOCK_SZ: usize = DEFAULT_BLOCK_SIZE,
> where
    R: RngCore + CryptoRng + Default,
    S: Storage<Id = u64>,
    C: Crypter,
{
    enclave: String,
    mappings: HashMap<String, u64>,
    links: HashMap<u64, u64>,
    inner: Passthrough,
    tree: BKeyTree<R, S, C, KEY_SZ>,
}

impl SDBTreeFs {
    pub fn new(
        enclave: impl AsRef<str>,
        metadir: impl AsRef<str>,
        datadir: impl AsRef<str>,
    ) -> SDBResult<Self> {
        Self::custom(
            enclave,
            datadir,
            DirectoryStorage::new(metadir.as_ref()).map_err(|_| Error::Storage)?,
        )
    }
}

impl<R, S, C, const KEY_SZ: usize, const BLOCK_SZ: usize> SDBTreeFs<R, S, C, KEY_SZ, BLOCK_SZ>
where
    R: RngCore + CryptoRng + Default,
    S: Storage<Id = u64>,
    C: Crypter,
{
    pub fn custom(
        enclave: impl AsRef<str>,
        datadir: impl AsRef<str>,
        storage: S,
    ) -> SDBResult<Self> {
        Ok(Self {
            enclave: enclave.as_ref().into(),
            mappings: HashMap::new(),
            links: HashMap::new(),
            inner: Passthrough::new::<&str>(datadir.as_ref().into()),
            tree: BKeyTree::with_storage(storage, utils::generate_key(&mut R::default()))
                .map_err(|_| Error::Storage)?,
        })
    }

    pub fn canonicalize(&self, path: &str) -> String {
        self.inner.canonicalize(path).to_string_lossy().to_string()
    }

    fn new_read_io(&self, path: &str) -> SDBResult<FromStd<File>> {
        Ok(FromStd::new(File::options().read(true).open(path)?))
    }

    fn new_write_io(&self, path: &str) -> SDBResult<FromStd<File>> {
        Ok(FromStd::new(
            File::options().write(true).create(true).open(path)?,
        ))
    }

    fn new_rw_io(&self, path: &str) -> SDBResult<FromStd<File>> {
        Ok(FromStd::new(
            File::options()
                .read(true)
                .write(true)
                .create(true)
                .open(path)?,
        ))
    }
}

impl<R, S, C, const KEY_SZ: usize, const BLOCK_SZ: usize> UnthreadedFileSystem
    for SDBTreeFs<R, S, C, KEY_SZ, BLOCK_SZ>
where
    R: RngCore + CryptoRng + Default,
    S: Storage<Id = u64>,
    C: Crypter,
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
            if mode & libc::S_IFMT > 0 {
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
        // We should technically be updating the blocks of the inode, but that is pretty hard to do
        // with this setup. We could possibly track the number of blocks covered by each inode.
        self.inner.unlink(path)
    }

    fn rmdir(&mut self, path: &str) -> Result<i32> {
        debug!("rmdir: path = {path}");
        self.inner.rmdir(path)
    }

    // fn symlink(&mut self, from: &str, to: &str) -> Result<i32> {
    //     debug!("symlink: from = {from}, to = {to}");

    //     let res = self.inner.symlink(from, to)?;
    //     if res == 0 {
    //         let from_ipath = self.inode_path(from);
    //         let to_ipath = self.inode_path(to);

    //         let khf_id = *self
    //             .mappings
    //             .get(&from_ipath)
    //             .ok_or(Error::MissingKhf(from_ipath))?;

    //         self.mappings.insert(to_ipath, khf_id);
    //         *self.links.entry(khf_id).or_insert(0) += 1;
    //     }

    //     Ok(res)
    // }

    // fn rename(&mut self, from: &str, to: &str, flags: c_uint) -> Result<i32> {
    //     debug!("rename: from = {from}, to = {to}");

    //     let res = self.inner.rename(from, to, flags)?;
    //     if res == 0 {
    //         let from_ipath = self.inode_path(from);
    //         let to_ipath = self.inode_path(to);

    //         let khf_id = self
    //             .mappings
    //             .remove(&from_ipath)
    //             .ok_or(Error::MissingKhf(from_ipath))?;

    //         self.mappings.insert(to_ipath, khf_id);
    //     }

    //     Ok(res)
    // }

    // fn link(&mut self, from: &str, to: &str) -> Result<i32> {
    //     debug!("link: from = {from}, to = {to}");

    //     let res = self.inner.link(from, to)?;
    //     if res == 0 {
    //         let from_ipath = self.inode_path(from);
    //         let to_ipath = self.inode_path(to);

    //         let khf_id = *self
    //             .mappings
    //             .get(&from_ipath)
    //             .ok_or(Error::MissingKhf(from_ipath))?;

    //         self.mappings.insert(to_ipath, khf_id);
    //         *self.links.entry(khf_id).or_insert(0) += 1;
    //     }

    //     Ok(res)
    // }

    // fn chmod(&mut self, path: &str, mode: mode_t, fi: Option<&mut fuse_file_info>) -> Result<i32> {
    //     debug!("chmod: path = {path}, mode = {}", Mode::from(mode | 0o666));
    //     self.inner.chmod(path, mode | 0o666, fi)
    // }

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
        let io = self.new_read_io(&ipath)?;
        let id = self.mappings.get(&ipath).unwrap();

        let mut tree = LocalizedBKeyTree::new(*id, &mut self.tree);
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
        let io = self.new_rw_io(&ipath)?;
        let id = self.mappings.get(&ipath).unwrap();

        let mut tree = LocalizedBKeyTree::new(*id, &mut self.tree);
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

    // fn fsync(
    //     &mut self,
    //     path: &str,
    //     isdatasync: c_int,
    //     fi: Option<&mut fuse_file_info>,
    // ) -> Result<i32> {
    //     debug!("fsync: path = {path}");
    //     let res = self.inner.fsync(path, isdatasync, fi)?;
    //     self.persist()?;
    //     Ok(res)
    // }

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

    // fn create(&mut self, path: &str, mode: mode_t, fi: Option<&mut fuse_file_info>) -> Result<i32> {
    //     debug!("create: path = {path}, mode = {}", Mode::from(mode | 0o666));

    //     let res = self.inner.create(path, mode | 0o666, fi)?;

    //     let ipath = self.inode_path(path);
    //     let khf_id = self.allocator.alloc().map_err(|_| Error::Alloc)?;

    //     self.mappings.insert(ipath, khf_id);
    //     *self.links.entry(khf_id).or_insert(0) += 1;

    //     self.inode_khfs
    //         .insert(khf_id, Khf::new(&self.inode_khf_fanouts, R::default()));

    //     self.master_khf.update(khf_id)?;

    //     Ok(res)
    // }

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

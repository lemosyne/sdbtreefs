use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error("missing mapping: {0}")]
    Mapping(String),

    #[error("allocation error")]
    Alloc,

    #[error("deallocation error: {0}")]
    Dealloc(u64),

    #[error("storage error")]
    Storage,

    #[error("enclave error")]
    Enclave,

    #[error(transparent)]
    Serde(#[from] bincode::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

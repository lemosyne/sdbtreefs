use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error("storage error")]
    Storage,
}

pub type Result<T> = std::result::Result<T, Error>;

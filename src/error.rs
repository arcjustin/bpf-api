use thiserror::Error;

use std::io::Error as IoError;
use std::num::{ParseIntError, TryFromIntError};

#[derive(Debug, Error)]
pub enum Error {
    #[error("a system error occurred")]
    SystemError(isize),

    #[error("an IO error occurred")]
    IoError(#[from] IoError),

    #[error("an error occurred when parsing an integer")]
    ParseIntError(#[from] ParseIntError),

    #[error("an error occurred when converting an integer")]
    TryFromIntError(#[from] TryFromIntError),

    #[error("unrecoverable error due to mutex poisoning")]
    MutexPoisoned,

    #[error("this isn't implemented")]
    NotImplemented,

    #[error("an invalid argument was given")]
    InvalidArgument,

    #[error("value was out of range")]
    OutOfRange,
}

pub type Result<T> = std::result::Result<T, Error>;

use thiserror::Error;

use std::io::Error as IoError;
use std::num::ParseIntError;

#[derive(Debug, Error)]
pub enum Error {
    #[error("a system error occurred")]
    SystemError(i64),

    #[error("an IO error occurred")]
    IoError(#[from] IoError),

    #[error("an error occurred when parsing an integer")]
    ParseIntError(#[from] ParseIntError),

    #[error("this isn't implemented")]
    NotImplemented,

    #[error("an invalid argument was given")]
    InvalidArgument,

    #[error("value was out of range")]
    OutOfRange,
}

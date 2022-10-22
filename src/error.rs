use std::fmt;
use std::io::Error as IoError;
use std::num::ParseIntError;

use peginator::ParseError as PeginatorError;

#[derive(Debug)]
pub enum Error {
    SystemError(i64),
    IoError(IoError),
    ParseIntError(ParseIntError),
    PeginatorError(PeginatorError),
    NotImplemented,
    InvalidArgument,
    OutOfRange,
}

impl From<IoError> for Error {
    fn from(err: IoError) -> Self {
        Self::IoError(err)
    }
}

impl From<ParseIntError> for Error {
    fn from(err: ParseIntError) -> Self {
        Self::ParseIntError(err)
    }
}

impl From<PeginatorError> for Error {
    fn from(err: PeginatorError) -> Self {
        Self::PeginatorError(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            Self::SystemError(n) => write!(f, "SystemError({})", n),
            Self::IoError(e) => write!(f, "IoError({})", e),
            Self::ParseIntError(e) => write!(f, "ParseIntError({})", e),
            Self::PeginatorError(e) => write!(f, "PeginatorError({})", e),
            Self::NotImplemented => write!(f, "NotImplemented"),
            Self::InvalidArgument => write!(f, "InvalidArgument"),
            Self::OutOfRange => write!(f, "OutOfRange"),
        }
    }
}

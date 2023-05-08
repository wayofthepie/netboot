use std::fmt::Debug;

use nom::error::{ErrorKind, ParseError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DhcpMessageError {
    #[error("invalid data received")]
    InvalidData,
    #[error("invalid operation")]
    InvalidOperation,
    #[error("invalid hardware type")]
    InvalidHardwareType(u8),
    #[error("invalid value for option")]
    InvalidValueForOptionMessageType(u8),
    #[error("not yet implemented")]
    NotYetImplemented,
    #[error("incomplete data")]
    IncompleteData,
    #[error("internal error: {0}")]
    NomError(String),
}

impl<I> ParseError<I> for DhcpMessageError
where
    I: Debug,
{
    fn from_error_kind(input: I, kind: ErrorKind) -> Self {
        DhcpMessageError::NomError(format!("failed on {input:?} with kind {kind:?}"))
    }

    fn append(_input: I, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

#[derive(Debug, PartialEq, Error)]
pub enum DhcpSerializeError {
    #[error("invalid dhcp option value")]
    InvalidDhcpOptionValue,
}

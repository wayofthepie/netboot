use nom::error::{ErrorKind, ParseError};

#[derive(Debug)]
pub enum DHCPMessageError<I> {
    InvalidData,
    InvalidOperation,
    InvalidHardwareType(u8),
    InvalidValueForOptionMessageType(u8),
    NotYetImplemented,
    NomError(nom::error::Error<I>),
}

impl<I> ParseError<I> for DHCPMessageError<I> {
    fn from_error_kind(input: I, kind: ErrorKind) -> Self {
        DHCPMessageError::NomError(nom::error::Error::new(input, kind))
    }

    fn append(_input: I, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

#[derive(Debug, PartialEq)]
pub enum DhcpSerializeError {
    InvalidDhcpOptionValue,
}

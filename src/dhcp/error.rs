use nom::error::{ErrorKind, ParseError};

#[derive(Debug)]
pub enum DHCPMessageError<I> {
    InvalidData,
    InvalidOperation,
    InvalidHardwareType(u8),
    NotYetImplemented,
    NomError(nom::error::Error<I>),
}

impl<'a> From<nom::error::Error<&'a [u8]>> for DHCPMessageError<&'a [u8]> {
    fn from(e: nom::error::Error<&'a [u8]>) -> Self {
        DHCPMessageError::NomError(e)
    }
}

impl<I> ParseError<I> for DHCPMessageError<I> {
    fn from_error_kind(input: I, kind: ErrorKind) -> Self {
        DHCPMessageError::NomError(nom::error::Error::new(input, kind))
    }

    fn append(_input: I, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

use casper_types::ApiError;

#[repr(u16)]
#[derive(Clone, Copy)]
pub enum Error {
    InvalidContext = 20000,
    InvalidKey,
    Phantom,
    FailedToGetArgBytes,
}

impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        ApiError::User(e as u16)
    }
}

pub fn as_u16(err: Error) -> u16 {
    err as u16
}

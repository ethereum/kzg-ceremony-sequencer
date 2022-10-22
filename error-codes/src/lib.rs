extern crate error_codes_derive;

pub use error_codes_derive::*;

pub trait ErrorCode {
    fn to_error_code(&self) -> &'static str;
}
use md4::{Digest, Md4};
use std::convert::From;
use utf16string::{LittleEndian, WString};

#[derive(Debug, PartialEq)]
#[repr(transparent)]
pub struct NtHash {
    bytes: [u8; 16],
}

impl AsRef<[u8; 16]> for NtHash {
    fn as_ref(&self) -> &[u8; 16] {
        &self.bytes
    }
}

impl From<[u8; 16]> for NtHash {
    fn from(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }
}

impl From<&str> for NtHash {
    fn from(item: &str) -> Self {
        let plaintext: WString<LittleEndian> = WString::from(item);
        let mut hasher = Md4::new();
        hasher.update(plaintext.into_bytes());
        let result = hasher.finalize();
        NtHash {
            bytes: result.into(),
        }
    }
}

impl NtHash {
    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

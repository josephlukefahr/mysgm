use core::error::Error;
use hex::{decode as hex_decode, encode as hex_encode};
use std::fs::{
    exists as file_exists, read_to_string as read_file_to_string, write as write_string_to_file,
};

#[derive(Debug, Clone)]
pub struct FileAdapter {
    path: String,
}

impl FileAdapter {
    pub fn new(path: &str) -> Self {
        Self { path: path.into() }
    }
    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
        let file = format!("{}/{}", self.path, key);
        match file_exists(&file)? {
            true => {
                let decoded_value = hex_decode(read_file_to_string(&file)?.trim())?;
                Ok(Some(decoded_value))
            }
            false => Ok(None),
        }
    }
    pub fn put_checked(&self, key: &str, value: &[u8]) -> Result<(), Box<dyn Error>> {
        let file = format!("{}/{}", self.path, key);
        match file_exists(&file)? {
            true => Err("Key already exists".into()),
            false => {
                write_string_to_file(&file, hex_encode(value))?;
                Ok(())
            }
        }
    }
}

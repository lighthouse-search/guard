use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};

pub async fn read(path: &str, offset: u64, chunk_size: u64) -> Option<Vec<u8>> {
    let file = File::open(path).expect("Failed to open file.");
    let mut reader = BufReader::new(file);

    reader.seek(SeekFrom::Start(offset)).expect("Failed to seek file.");

    let mut buffer = vec![0u8; chunk_size as usize];

    let bytes_read = reader.read(&mut buffer).expect("Failed to read file.");
    if bytes_read == 0 {
        return None; // EOF
    }

    Some(buffer[..bytes_read].to_vec())
}
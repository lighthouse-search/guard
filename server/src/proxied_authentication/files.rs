use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

pub fn write_file(file_path: String, data: String) {
    // Check if the file already exists
    if Path::new(&file_path).exists() {
        log::info!("File already exists.");
    } else {
        // Create the file and write to it only if it doesn't already exist
        let mut file = match OpenOptions::new().write(true).create_new(true).open(file_path) {
            Ok(file) => file,
            Err(e) => panic!("Could not create file: {}", e),
        };

        match write!(file, "{}", data) {
            Ok(_) => log::info!("Successfully wrote to the file."),
            Err(e) => panic!("Could not write to file: {}", e),
        }
    }
}

use std::fs::OpenOptions;
use std::io::Write;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};


pub fn log_time() {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("time_recorder.txt")
        .expect("[log_time] cannot open the file");

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("[log_time] time error")
        .as_nanos();

    if let Err(err) = writeln!(file, "[server output]:{}", timestamp) {
        eprintln!("[log_time] fail to write: {}", err);
    } else {
        println!("[log_time] ✅already log!");
    }
        
}
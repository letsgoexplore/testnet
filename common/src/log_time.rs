use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn log_detailed_duration(event: &str, duration: u128) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("time_recorder_all.txt")
        .expect("[log_time] cannot open the file");

    if let Err(err) = writeln!(file, "{}:{:?}", event, duration) {
        eprintln!("[log_time] fail to write: {}", err);
    } else {
        println!("[log_time] ✅already log!");
    }
}

pub fn log_detailed_time(event: String) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("time_recorder_detailed_timestamp.txt")
        .expect("[log_time] cannot open the file");

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("[log_time] time error")
        .as_nanos();

    if let Err(err) = writeln!(file, "{}:{:?}", event, timestamp) {
        eprintln!("[log_time] fail to write: {}", err);
    } else {
        println!("[log_time] ✅already log!");
    }
}

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

    if let Err(err) = writeln!(file, "{}", timestamp) {
        eprintln!("[log_time] fail to write: {}", err);
    } else {
        println!("[log_time] ✅already log!");
    }
}

pub fn log_duration(duration: u128) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("time_recorder.txt")
        .expect("[log_time] cannot open the file");

    if let Err(err) = writeln!(file, "{:?}", duration) {
        eprintln!("[log_time] fail to write: {}", err);
    } else {
        println!("[log_time] ✅already log!");
    }
}

pub fn log_server_time(event: &str) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("detailed_time_recorder.txt")
        .expect("[log_time] cannot open the file");

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("[log_time] time error")
        .as_nanos();

    if let Err(err) = writeln!(file, "f{}:{}", timestamp, event) {
        eprintln!("[log_time] fail to write: {}", err);
    } else {
        println!("[log_time] ✅already log!");
    }
}

pub fn log_client_encrypt_time(duration: u128) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("client_encrypt_time_recorder.txt")
        .expect("[log_time] cannot open the file");

    if let Err(err) = writeln!(file, "{:?}", duration) {
        eprintln!("[log_time] fail to write: {}", err);
    } else {
        println!("[log_time] ✅already log!");
    }
}

pub fn log_agg_encrypt_time(duration: u128) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("agg_encrypt_time_recorder.txt")
        .expect("[log_time] cannot open the file");

    if let Err(err) = writeln!(file, "{:?}", duration) {
        eprintln!("[log_time] fail to write: {}", err);
    } else {
        println!("[log_time] ✅already log!");
    }
}

pub fn log_client_time() {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("client_time_recorder.txt")
        .expect("[log_time] cannot open the file");

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("[log_time] time error")
        .as_nanos();

    if let Err(err) = writeln!(file, "{}", timestamp) {
        eprintln!("[log_time] fail to write: {}", err);
    } else {
        println!("[log_time] ✅client time already log!");
    }
}

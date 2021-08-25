use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    fs::File,
    io::{BufRead, BufReader, Read, Write},
    path::Path,
};

/// file -> base64::decode -> cbor::decode
pub fn parse_from_file<P, D>(path: P) -> Result<D, Box<dyn Error>>
where
    P: AsRef<Path>,
    D: for<'a> Deserialize<'a>,
{
    let mut f = File::open(path)?;
    let dec = base64::read::DecoderReader::new(&mut f, base64::STANDARD);
    Ok(serde_cbor::from_reader(dec)?)
}

/// cbor::encode -> base64::encode -> file
pub fn save_to_file<P, S>(path: P, val: &S) -> Result<(), Box<dyn Error>>
where
    P: AsRef<Path>,
    S: Serialize,
{
    let mut f = File::create(path)?;
    let mut enc = base64::write::EncoderWriter::new(&mut f, base64::STANDARD);
    Ok(serde_cbor::to_writer(&mut enc, val)?)
}

/// file -> separate by newline -> [base64::decode] -> [cbor::decode]
pub fn parse_multi_from_file<P, D>(path: P) -> Result<Vec<D>, Box<dyn Error>>
where
    P: AsRef<Path>,
    D: for<'a> Deserialize<'a>,
{
    let mut values = Vec::new();

    let mut f = BufReader::new(File::open(path)?);
    for line in f.lines() {
        // Skip empty lines
        let mut line = line?.into_bytes();
        if line.len() == 0 {
            continue;
        }

        let mut cursor = line.as_slice();
        let dec = base64::read::DecoderReader::new(&mut cursor, base64::STANDARD);
        let val = serde_cbor::from_reader(dec)?;
        values.push(val);
    }

    Ok(values)
}

/// cbor::encode -> base64::encode -> file
pub fn save_multi_to_file<P, S>(path: P, values: &[S]) -> Result<(), Box<dyn Error>>
where
    P: AsRef<Path>,
    S: Serialize,
{
    let mut f = File::create(path)?;
    for val in values {
        // Write the value
        {
            let mut enc = base64::write::EncoderWriter::new(&mut f, base64::STANDARD);
            serde_cbor::to_writer(&mut enc, val)?;
        }

        // Write a newline
        f.write(b"\n")?;
    }

    Ok(())
}

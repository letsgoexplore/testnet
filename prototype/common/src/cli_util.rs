use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    io::{BufRead, BufReader, Read, Write},
};

/// file -> base64::decode -> cbor::decode
pub fn load<R, D>(f: R) -> Result<D, Box<dyn Error>>
where
    R: Read,
    D: for<'a> Deserialize<'a>,
{
    let val = load_multi(f)?.pop().unwrap();
    Ok(val)
}

/// cbor::encode -> base64::encode -> file
pub fn save<W, S>(f: W, val: &S) -> Result<(), Box<dyn Error>>
where
    W: Write,
    S: Serialize,
{
    save_multi(f, &[val])
}

/// file -> separate by newline -> [base64::decode] -> [cbor::decode]
pub fn load_multi<R, D>(mut f: R) -> Result<Vec<D>, Box<dyn Error>>
where
    R: Read,
    D: for<'a> Deserialize<'a>,
{
    let mut values = Vec::new();

    let f = BufReader::new(&mut f);
    for line in f.lines() {
        // Skip empty lines
        let line = line?.into_bytes();
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
pub fn save_multi<W, S>(mut f: W, values: &[S]) -> Result<(), Box<dyn Error>>
where
    W: Write,
    S: Serialize,
{
    let num_vals = values.len();
    for (i, val) in values.iter().enumerate() {
        // Write the value
        {
            let mut enc = base64::write::EncoderWriter::new(&mut f, base64::STANDARD);
            serde_cbor::to_writer(&mut enc, val)?;
        }

        // Write a newline between entries
        if i < num_vals - 1 {
            f.write(b"\n")?;
        }
    }

    Ok(())
}

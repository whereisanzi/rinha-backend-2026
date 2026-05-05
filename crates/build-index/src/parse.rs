use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::time::Instant;

use flate2::read::GzDecoder;
use serde::Deserialize;
use serde::de::{Deserializer, SeqAccess, Visitor};

use crate::DIM;

#[derive(Deserialize)]
struct Entry {
    vector: [f32; DIM],
    label: String,
}

struct Collector {
    vectors: Vec<[f32; DIM]>,
    labels: Vec<u8>,
}

impl<'de> Visitor<'de> for Collector {
    type Value = (Vec<[f32; DIM]>, Vec<u8>);

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "an array of references")
    }

    fn visit_seq<A: SeqAccess<'de>>(mut self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut last_log = Instant::now();
        while let Some(e) = seq.next_element::<Entry>()? {
            self.vectors.push(e.vector);
            self.labels.push(if e.label == "fraud" { 1 } else { 0 });
            if self.vectors.len() % 500_000 == 0 && last_log.elapsed().as_secs() >= 1 {
                eprintln!("  parsed {} vectors", self.vectors.len());
                last_log = Instant::now();
            }
        }
        Ok((self.vectors, self.labels))
    }
}

pub fn load(path: &Path) -> std::io::Result<(Vec<[f32; DIM]>, Vec<u8>)> {
    let file = File::open(path)?;
    let gz = GzDecoder::new(BufReader::with_capacity(1 << 20, file));
    let mut de = serde_json::Deserializer::from_reader(BufReader::with_capacity(1 << 20, gz));
    de.deserialize_seq(Collector {
        vectors: Vec::with_capacity(3_100_000),
        labels: Vec::with_capacity(3_100_000),
    })
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

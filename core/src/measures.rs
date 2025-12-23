use crate::corpus::Corpus;
use std::collections::HashMap;

/// Calcule l'entropie de Shannon d'une séquence d'octets
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq: HashMap<u8, usize> = HashMap::new();
    for &byte in data {
        *freq.entry(byte).or_insert(0) += 1;
    }

    let len = data.len() as f64;
    freq.values()
        .map(|&count| {
            let p = count as f64 / len;
            if p > 0.0 {
                -p * p.log2()
            } else {
                0.0
            }
        })
        .sum()
}

/// Calcule l'entropie par offset dans les PDUs
pub fn entropy_by_offset(corpus: &Corpus, max_offset: usize) -> Vec<f64> {
    let mut samples: Vec<Vec<u8>> = vec![Vec::new(); max_offset];

    for pdu in &corpus.items {
        let slice = pdu.as_slice();
        for (i, &byte) in slice.iter().enumerate() {
            if i < max_offset {
                samples[i].push(byte);
            }
        }
    }

    samples.iter().map(|s| entropy(s)).collect()
}

/// Gain d'alignement après réalignement
#[derive(Debug, Clone)]
pub struct AlignmentGain {
    pub original_entropy: f64,
    pub aligned_entropy: f64,
    pub gain_bits: f64,
    pub anchor_offsets: Vec<usize>,
}

impl AlignmentGain {
    pub fn compute(
        corpus: &Corpus,
        anchor_offsets: &[usize],
        max_offset: usize,
    ) -> Self {
        let original = entropy_by_offset(corpus, max_offset);
        let original_entropy: f64 = original.iter().sum();

        // Réaligner selon les ancres
        let mut aligned_samples: Vec<Vec<u8>> = vec![Vec::new(); max_offset];
        for pdu in &corpus.items {
            let slice = pdu.as_slice();
            for &anchor in anchor_offsets {
                if anchor < slice.len() && anchor < max_offset {
                    aligned_samples[anchor].push(slice[anchor]);
                }
            }
        }

        let aligned: Vec<f64> = aligned_samples.iter().map(|s| entropy(s)).collect();
        let aligned_entropy: f64 = aligned.iter().sum();

        let gain_bits = (original_entropy - aligned_entropy) * corpus.total_bytes() as f64 / 8.0;

        Self {
            original_entropy,
            aligned_entropy,
            gain_bits,
            anchor_offsets: anchor_offsets.to_vec(),
        }
    }
}

/// Calcule la taille compressée (proxy pour MDL data)
pub fn compressed_size(data: &[u8]) -> crate::Result<usize> {
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use std::io::Write;

    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    let compressed = encoder.finish()?;
    Ok(compressed.len())
}


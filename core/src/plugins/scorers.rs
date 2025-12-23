use crate::corpus::Corpus;
use crate::hypothesis::Hypothesis;
use crate::measures::{compressed_size, entropy};
use crate::parser::ParsedCorpus;
use crate::plugin::Scorer;
use crate::score::{Score, ScoreBreakdown};

/// Scoreur MDL standard
pub struct MdlScorer {
    pub min_parse_success_ratio: f64,
}

impl MdlScorer {
    pub fn new() -> Self {
        Self {
            min_parse_success_ratio: 0.95,
        }
    }
}

impl Default for MdlScorer {
    fn default() -> Self {
        Self::new()
    }
}

impl Scorer for MdlScorer {
    fn name(&self) -> &'static str {
        "MdlScorer"
    }

    fn score(
        &self,
        corpus: &Corpus,
        parsed: &ParsedCorpus,
        h: &Hypothesis,
    ) -> Score {
        let parse_success_ratio = parsed.parse_success_ratio();

        // Contrainte dure : PSR doit être >= seuil
        if parse_success_ratio < self.min_parse_success_ratio {
            return Score::new(ScoreBreakdown {
                mdl_model_bits: f64::INFINITY,
                mdl_data_bits: f64::INFINITY,
                parse_success_ratio,
                alignment_gain_bits: 0.0,
                entropy_drop_bits: 0.0,
                penalties_bits: f64::INFINITY,
            });
        }

        // MDL Model : complexité de l'hypothèse
        let mdl_model_bits = estimate_model_bits(h);

        // MDL Data : entropie + compression des SDUs
        let mut sdu_data = Vec::new();
        let mut total_sdu_bytes = 0;

        for (pdu, parsed_pdu) in corpus.items.iter().zip(parsed.parsed_pdus.iter()) {
            for segment in &parsed_pdu.segments {
                if matches!(segment.kind, crate::segment::SegmentKind::Sdu) {
                    let slice = &pdu.as_slice()[segment.range.clone()];
                    sdu_data.extend_from_slice(slice);
                    total_sdu_bytes += slice.len();
                }
            }
        }

        let mdl_data_bits = if !sdu_data.is_empty() {
            // Entropie empirique
            let sdu_entropy = entropy(&sdu_data);
            let entropy_bits = sdu_entropy * total_sdu_bytes as f64;

            // Compression proxy
            let compressed_bits = match compressed_size(&sdu_data) {
                Ok(size) => size as f64 * 8.0,
                Err(_) => entropy_bits,
            };

            // Prendre le minimum (meilleur modèle)
            entropy_bits.min(compressed_bits)
        } else {
            // Pas de SDU extrait = pénalité
            corpus.total_bytes() as f64 * 8.0
        };

        // Pénalités
        let mut penalties_bits = 0.0;

        // Pénalité pour sur-découpage (trop de segments)
        let avg_segments = parsed
            .parsed_pdus
            .iter()
            .map(|p| p.segments.len())
            .sum::<usize>() as f64
            / parsed.parsed_pdus.len().max(1) as f64;

        if avg_segments > 10.0 {
            penalties_bits += (avg_segments - 10.0) * 8.0;
        }

        // Pénalité pour exceptions
        let exception_count: usize = parsed
            .parsed_pdus
            .iter()
            .map(|p| p.exceptions.len())
            .sum();
        penalties_bits += exception_count as f64 * 16.0;

        // Pénalité pour segments trop petits
        let small_segments = parsed
            .parsed_pdus
            .iter()
            .flat_map(|p| &p.segments)
            .filter(|s| s.len() < 2)
            .count();
        penalties_bits += small_segments as f64 * 4.0;

        Score::new(ScoreBreakdown {
            mdl_model_bits,
            mdl_data_bits,
            parse_success_ratio,
            alignment_gain_bits: 0.0, // TODO: calculer si nécessaire
            entropy_drop_bits: 0.0,    // TODO: calculer si nécessaire
            penalties_bits,
        })
    }
}

/// Estime les bits nécessaires pour encoder le modèle
fn estimate_model_bits(h: &Hypothesis) -> f64 {
    match h {
        Hypothesis::LengthPrefixBundle { .. } => 32.0,
        Hypothesis::DelimiterBundle { pattern } => 16.0 + pattern.len() as f64 * 8.0,
        Hypothesis::FixedHeader { len } => 16.0 + (*len as f64).log2() * 2.0,
        Hypothesis::ExtensibleBitmap { .. } => 40.0,
        Hypothesis::Tlv { .. } => 24.0,
        Hypothesis::VarintKeyWireType { .. } => 24.0,
    }
}


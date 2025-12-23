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

        // MDL Data : bits pour encoder les données selon le modèle
        // MDL(Data|Model) = bits(PCI) + bits(SDU)
        // où PCI = Protocol Control Information (headers) et SDU = Service Data Unit (payloads)
        
        let mut pci_data = Vec::new();
        let mut sdu_data = Vec::new();
        let mut field_data = Vec::new();
        let mut total_pci_bytes = 0;
        let mut total_sdu_bytes = 0;
        let mut _total_field_bytes = 0;

        for (pdu, parsed_pdu) in corpus.items.iter().zip(parsed.parsed_pdus.iter()) {
            for segment in &parsed_pdu.segments {
                let slice = &pdu.as_slice()[segment.range.clone()];
                match segment.kind {
                    crate::segment::SegmentKind::Pci => {
                        pci_data.extend_from_slice(slice);
                        total_pci_bytes += slice.len();
                    }
                    crate::segment::SegmentKind::Sdu => {
                        sdu_data.extend_from_slice(slice);
                        total_sdu_bytes += slice.len();
                    }
                    crate::segment::SegmentKind::Field(_) => {
                        field_data.extend_from_slice(slice);
                        _total_field_bytes += slice.len();
                    }
                    _ => {
                        // Ignorer les autres types (Error, MessageBoundary, etc.)
                    }
                }
            }
        }

        // Calculer les bits pour encoder les données selon le modèle
        // On combine PCI + Fields + SDU car ils font tous partie des données encodées
        let mdl_data_bits = {
            // Construire les données complètes selon le modèle
            let mut model_data = Vec::new();
            model_data.extend_from_slice(&pci_data);
            model_data.extend_from_slice(&field_data);
            model_data.extend_from_slice(&sdu_data);
            
            if !model_data.is_empty() {
                // Calculer l'entropie empirique
                let model_entropy = entropy(&model_data);
                let total_model_bytes = model_data.len();
                let entropy_bits = model_entropy * total_model_bytes as f64;

                // Compression proxy (meilleur estimateur de la taille réelle)
                let compressed_bits = match compressed_size(&model_data) {
                    Ok(size) => size as f64 * 8.0,
                    Err(_) => entropy_bits,
                };

                // Prendre le minimum entre entropie et compression
                // La compression est généralement meilleure car elle capture les patterns
                entropy_bits.min(compressed_bits)
            } else {
                // Pas de données extraites = pénalité maximale
                corpus.total_bytes() as f64 * 8.0
            }
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

        // Calculer le gain d'entropie : comparaison avec les données brutes
        // Si les données selon le modèle (PCI+Fields+SDU) sont plus régulières que les données brutes, on gagne des bits
        let entropy_drop_bits = {
            // Calculer l'entropie des données brutes
            let raw_data: Vec<u8> = corpus.items.iter()
                .flat_map(|p| p.as_slice())
                .copied()
                .collect();
            let raw_entropy = entropy(&raw_data);
            let raw_entropy_bits = raw_entropy * raw_data.len() as f64;
            
            // Calculer l'entropie des données selon le modèle (PCI + Fields + SDU)
            let mut model_data = Vec::new();
            model_data.extend_from_slice(&pci_data);
            model_data.extend_from_slice(&field_data);
            model_data.extend_from_slice(&sdu_data);
            
            if !model_data.is_empty() && model_data.len() == raw_data.len() {
                // Si les tailles correspondent, on peut comparer directement
                let model_entropy = entropy(&model_data);
                let model_entropy_bits = model_entropy * model_data.len() as f64;
                
                // Le gain = réduction d'entropie (si positive)
                // On ne soustrait que si les données selon le modèle sont vraiment plus régulières
                let gain = raw_entropy_bits - model_entropy_bits;
                gain.max(0.0) // Pas de gain négatif
            } else {
                // Si les tailles ne correspondent pas, pas de gain calculé
                0.0
            }
        };

        Score::new(ScoreBreakdown {
            mdl_model_bits,
            mdl_data_bits,
            parse_success_ratio,
            alignment_gain_bits: 0.0, // TODO: calculer si nécessaire (pour ExtensibleBitmap)
            entropy_drop_bits,
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


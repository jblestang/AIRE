use serde::{Deserialize, Serialize};

/// Breakdown détaillé du score MDL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    /// Bits pour encoder le modèle
    pub mdl_model_bits: f64,
    /// Bits pour encoder les données selon le modèle
    pub mdl_data_bits: f64,
    /// Ratio de succès du parsing (0.0-1.0)
    pub parse_success_ratio: f64,
    /// Gain d'alignement (bits économisés)
    pub alignment_gain_bits: f64,
    /// Réduction d'entropie (bits économisés)
    pub entropy_drop_bits: f64,
    /// Pénalités diverses
    pub penalties_bits: f64,
}

impl ScoreBreakdown {
    pub fn total_bits(&self) -> f64 {
        self.mdl_model_bits
            + self.mdl_data_bits
            - self.alignment_gain_bits
            - self.entropy_drop_bits
            + self.penalties_bits
    }
}

/// Score complet d'une hypothèse
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Score {
    pub breakdown: ScoreBreakdown,
    pub total_bits: f64,
}

impl Score {
    pub fn new(breakdown: ScoreBreakdown) -> Self {
        let total_bits = breakdown.total_bits();
        Self {
            breakdown,
            total_bits,
        }
    }
}

impl PartialOrd for Score {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.total_bits.partial_cmp(&other.total_bits)
    }
}

impl PartialEq for Score {
    fn eq(&self, other: &Self) -> bool {
        self.total_bits == other.total_bits
    }
}

impl Ord for Score {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.total_bits
            .partial_cmp(&other.total_bits)
            .unwrap_or(std::cmp::Ordering::Equal)
    }
}

impl Eq for Score {}


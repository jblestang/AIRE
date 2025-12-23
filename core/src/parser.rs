use crate::{corpus::Corpus, hypothesis::Hypothesis, segment::Segment};

/// Résultat du parsing d'une PDU
#[derive(Debug, Clone)]
pub struct ParsedPdu {
    pub segments: Vec<Segment>,
    pub exceptions: Vec<String>,
}

impl ParsedPdu {
    pub fn new(segments: Vec<Segment>) -> Self {
        Self {
            segments,
            exceptions: Vec::new(),
        }
    }

    pub fn with_exception(mut self, msg: String) -> Self {
        self.exceptions.push(msg);
        self
    }

    /// Extrait les SDUs de cette PDU parsée
    pub fn sdus(&self) -> Vec<std::ops::Range<usize>> {
        self.segments
            .iter()
            .filter_map(|s| {
                if matches!(s.kind, crate::segment::SegmentKind::Sdu) {
                    Some(s.range.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Vérifie si le parsing a réussi (pas d'erreurs)
    pub fn is_success(&self) -> bool {
        !self.segments.iter().any(|s| {
            matches!(s.kind, crate::segment::SegmentKind::Error(_))
        })
    }
}

/// Résultat du parsing d'un corpus
#[derive(Debug, Clone)]
pub struct ParsedCorpus {
    pub parsed_pdus: Vec<ParsedPdu>,
    pub diagnostics: Vec<String>,
}

impl ParsedCorpus {
    pub fn new(parsed_pdus: Vec<ParsedPdu>) -> Self {
        Self {
            parsed_pdus,
            diagnostics: Vec::new(),
        }
    }

    pub fn parse_success_ratio(&self) -> f64 {
        if self.parsed_pdus.is_empty() {
            return 0.0;
        }
        let success_count = self
            .parsed_pdus
            .iter()
            .filter(|p| p.is_success())
            .count();
        success_count as f64 / self.parsed_pdus.len() as f64
    }
}

/// Trait pour les parseurs de protocole
pub trait Parser: Send + Sync {
    fn name(&self) -> &'static str;

    fn applicable(&self, h: &Hypothesis) -> bool;

    fn parse_corpus(&self, corpus: &Corpus, h: &Hypothesis) -> ParsedCorpus;
}

/// Type de segment (réexport pour compatibilité)
pub use crate::segment::SegmentKind;


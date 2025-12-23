use serde::{Deserialize, Serialize};

/// Type de segment dans une PDU parsée
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SegmentKind {
    /// PCI (Protocol Control Information)
    Pci,
    /// SDU (Service Data Unit)
    Sdu,
    /// Frontière entre messages (pour bundling)
    MessageBoundary,
    /// Champ de longueur
    Field(String),
    /// Erreur de parsing
    Error(String),
}

/// Segment d'une PDU parsée
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Segment {
    pub kind: SegmentKind,
    pub range: std::ops::Range<usize>,
    pub note: Option<String>,
}

impl Segment {
    pub fn new(kind: SegmentKind, range: std::ops::Range<usize>) -> Self {
        Self {
            kind,
            range,
            note: None,
        }
    }

    pub fn with_note(mut self, note: String) -> Self {
        self.note = Some(note);
        self
    }

    pub fn len(&self) -> usize {
        self.range.end - self.range.start
    }
}


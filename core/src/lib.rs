pub mod corpus;
pub mod error;
pub mod hypothesis;
pub mod inference;
pub mod measures;
pub mod parser;
pub mod pcap;
pub mod plugin;
pub mod plugins;
pub mod score;
pub mod segment;

#[cfg(test)]
mod tests;

pub use corpus::{Corpus, Flow, PduRef, UdpDatagram};
pub use error::{Error, Result};
pub use hypothesis::Hypothesis;
pub use inference::{InferenceEngine, InferenceResult, Layer};
pub use measures::{entropy, entropy_by_offset, AlignmentGain};
pub use parser::{ParsedCorpus, ParsedPdu, Parser, SegmentKind};
pub use plugin::{HypothesisGenerator, PluginRegistry, Scorer};
pub use score::{Score, ScoreBreakdown};
pub use segment::Segment;

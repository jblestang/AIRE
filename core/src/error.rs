use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("PCAP parsing error: {0}")]
    PcapParse(String),

    #[error("Invalid hypothesis: {0}")]
    InvalidHypothesis(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid range: {0}")]
    InvalidRange(String),

    #[error("Plugin error: {0}")]
    Plugin(String),
}

pub type Result<T> = std::result::Result<T, Error>;


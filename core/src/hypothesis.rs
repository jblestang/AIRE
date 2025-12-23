use serde::{Deserialize, Serialize};

/// Hypothèse sur la structure d'une couche protocolaire
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Hypothesis {
    /// Bundling avec préfixe de longueur
    LengthPrefixBundle {
        offset: usize,
        width: LengthWidth,
        endian: Endianness,
        includes_header: bool,
    },
    /// Bundling avec délimiteur
    DelimiterBundle {
        pattern: Vec<u8>,
    },
    /// En-tête fixe
    FixedHeader {
        len: usize,
    },
    /// Bitmap extensible (PER-like)
    ExtensibleBitmap {
        start: usize,
        cont_bit: u8,
        stop_value: u8,
        max_bytes: usize,
    },
    /// TLV (BER-like)
    Tlv {
        tag_offset: usize,
        tag_bytes: usize,
        len_offset: usize,  // Offset relatif au début du tag
        len_rule: TlvLenRule,
        length_includes_header: bool, // Si true, le length inclut tag+length
    },
    /// Varint fields (protobuf-like)
    VarintKeyWireType {
        key_max_bytes: usize,
        allow_embedded: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LengthWidth {
    One = 1,
    Two = 2,
    Four = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TlvLenRule {
    DefiniteShort,    // 1 byte
    DefiniteMedium,   // 2 bytes
    DefiniteLong,     // 4 bytes
    IndefiniteWithEoc,
}

impl Hypothesis {
    pub fn name(&self) -> &'static str {
        match self {
            Hypothesis::LengthPrefixBundle { .. } => "LengthPrefixBundle",
            Hypothesis::DelimiterBundle { .. } => "DelimiterBundle",
            Hypothesis::FixedHeader { .. } => "FixedHeader",
            Hypothesis::ExtensibleBitmap { .. } => "ExtensibleBitmap",
            Hypothesis::Tlv { .. } => "TLV",
            Hypothesis::VarintKeyWireType { .. } => "VarintKeyWireType",
        }
    }
}


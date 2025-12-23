use crate::corpus::Corpus;
use crate::hypothesis::{Endianness, Hypothesis, LengthWidth, TlvLenRule};
use crate::plugin::HypothesisGenerator;

/// Générateur d'hypothèses pour length-prefix bundling
pub struct LengthPrefixGenerator;

impl HypothesisGenerator for LengthPrefixGenerator {
    fn name(&self) -> &'static str {
        "LengthPrefixGenerator"
    }

    fn propose(&self, corpus: &Corpus) -> Vec<Hypothesis> {
        let mut hypotheses = Vec::new();

        if corpus.is_empty() {
            return hypotheses;
        }

        // Générer des hypothèses pour différentes configurations
        for offset in 0..=4 {
            for width in [LengthWidth::One, LengthWidth::Two, LengthWidth::Four] {
                for endian in [Endianness::Little, Endianness::Big] {
                    hypotheses.push(Hypothesis::LengthPrefixBundle {
                        offset,
                        width,
                        endian,
                        includes_header: false,
                    });
                }
            }
        }

        hypotheses
    }
}

/// Générateur d'hypothèses pour delimiter bundling
pub struct DelimiterGenerator;

impl HypothesisGenerator for DelimiterGenerator {
    fn name(&self) -> &'static str {
        "DelimiterGenerator"
    }

    fn propose(&self, corpus: &Corpus) -> Vec<Hypothesis> {
        let mut hypotheses = Vec::new();

        if corpus.is_empty() {
            return hypotheses;
        }

        // Patterns communs
        let patterns = vec![
            vec![0x00, 0x00], // Double null
            vec![0x0A],       // LF
            vec![0x0D, 0x0A], // CRLF
            vec![0xFF, 0xFF], // Double 0xFF
        ];

        for pattern in patterns {
            hypotheses.push(Hypothesis::DelimiterBundle { pattern });
        }

        hypotheses
    }
}

/// Générateur d'hypothèses pour fixed header
pub struct FixedHeaderGenerator;

impl HypothesisGenerator for FixedHeaderGenerator {
    fn name(&self) -> &'static str {
        "FixedHeaderGenerator"
    }

    fn propose(&self, corpus: &Corpus) -> Vec<Hypothesis> {
        let mut hypotheses = Vec::new();

        if corpus.is_empty() {
            return hypotheses;
        }

        // Générer des headers de 2 à 32 octets
        for len in 2..=32.min(corpus.items[0].len()) {
            hypotheses.push(Hypothesis::FixedHeader { len });
        }

        hypotheses
    }
}

/// Générateur d'hypothèses pour bitmap extensible
pub struct ExtensibleBitmapGenerator;

impl HypothesisGenerator for ExtensibleBitmapGenerator {
    fn name(&self) -> &'static str {
        "ExtensibleBitmapGenerator"
    }

    fn propose(&self, corpus: &Corpus) -> Vec<Hypothesis> {
        let mut hypotheses = Vec::new();

        if corpus.is_empty() {
            return hypotheses;
        }

        for start in 0..=4 {
            for cont_bit in 0..8 {
                for stop_value in [0u8, 1u8] {
                    hypotheses.push(Hypothesis::ExtensibleBitmap {
                        start,
                        cont_bit,
                        stop_value,
                        max_bytes: 8,
                    });
                }
            }
        }

        hypotheses
    }
}

/// Générateur d'hypothèses pour TLV
pub struct TlvGenerator;

impl HypothesisGenerator for TlvGenerator {
    fn name(&self) -> &'static str {
        "TlvGenerator"
    }

    fn propose(&self, _corpus: &Corpus) -> Vec<Hypothesis> {
        vec![
            Hypothesis::Tlv {
                tag_bytes: 1,
                len_rule: TlvLenRule::DefiniteShort,
            },
            Hypothesis::Tlv {
                tag_bytes: 1,
                len_rule: TlvLenRule::DefiniteLong,
            },
            Hypothesis::Tlv {
                tag_bytes: 1,
                len_rule: TlvLenRule::IndefiniteWithEoc,
            },
            Hypothesis::Tlv {
                tag_bytes: 2,
                len_rule: TlvLenRule::DefiniteShort,
            },
        ]
    }
}

/// Générateur d'hypothèses pour varint
pub struct VarintGenerator;

impl HypothesisGenerator for VarintGenerator {
    fn name(&self) -> &'static str {
        "VarintGenerator"
    }

    fn propose(&self, _corpus: &Corpus) -> Vec<Hypothesis> {
        vec![
            Hypothesis::VarintKeyWireType {
                key_max_bytes: 5,
                allow_embedded: false,
            },
            Hypothesis::VarintKeyWireType {
                key_max_bytes: 5,
                allow_embedded: true,
            },
            Hypothesis::VarintKeyWireType {
                key_max_bytes: 10,
                allow_embedded: false,
            },
        ]
    }
}


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
        let mut hypotheses = Vec::new();
        
        // Générer toutes les combinaisons pertinentes
        // tag_offset: où commence le tag (0, 1, 2)
        // tag_bytes: taille du tag (1, 2, 3)
        // len_offset: où commence le length par rapport au début du tag (tag_bytes, tag_bytes+1, etc.)
        for tag_offset in 0..=2 {
            for tag_bytes in 1..=3 {
                // Le length peut être juste après le tag, ou avec un petit décalage
                for len_offset_delta in 0..=1 {
                    let len_offset = tag_offset + tag_bytes + len_offset_delta;
                    
                    for len_rule in [
                        TlvLenRule::DefiniteShort,   // 1 byte length
                        TlvLenRule::DefiniteMedium,  // 2 bytes length
                        TlvLenRule::DefiniteLong,    // 4 bytes length
                    ] {
                        // Tester avec et sans length incluant le header
                        for length_includes_header in [false, true] {
                            hypotheses.push(Hypothesis::Tlv {
                                tag_offset,
                                tag_bytes,
                                len_offset,
                                len_rule,
                                length_includes_header,
                            });
                        }
                    }
                }
            }
        }
        
        hypotheses
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


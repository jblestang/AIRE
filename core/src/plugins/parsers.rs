use crate::corpus::Corpus;
use crate::hypothesis::{
    Endianness, Hypothesis, LengthWidth, TlvLenRule,
};
use crate::parser::{ParsedCorpus, ParsedPdu, Parser};
use crate::segment::{Segment, SegmentKind};

/// Parseur pour length-prefix bundling
pub struct LengthPrefixParser;

impl Parser for LengthPrefixParser {
    fn name(&self) -> &'static str {
        "LengthPrefixParser"
    }

    fn applicable(&self, h: &Hypothesis) -> bool {
        matches!(h, Hypothesis::LengthPrefixBundle { .. })
    }

    fn parse_corpus(&self, corpus: &Corpus, h: &Hypothesis) -> ParsedCorpus {
        let Hypothesis::LengthPrefixBundle {
            offset,
            width,
            endian,
            includes_header: _,
        } = h
        else {
            return ParsedCorpus::new(vec![]);
        };

        let mut parsed_pdus = Vec::new();

        for pdu in &corpus.items {
            let data = pdu.as_slice();
            let mut segments = Vec::new();
            let mut pos = 0;
            let mut exceptions = Vec::new();

            while pos < data.len() {
                let len_pos = pos + *offset;
                if len_pos + (*width as usize) > data.len() {
                    segments.push(Segment::new(
                        SegmentKind::Error("Incomplete length field".to_string()),
                        pos..data.len(),
                    ));
                    break;
                }

                let len = match (width, endian) {
                    (LengthWidth::One, _) => data[len_pos] as usize,
                    (LengthWidth::Two, Endianness::Little) => {
                        u16::from_le_bytes([data[len_pos], data[len_pos + 1]]) as usize
                    }
                    (LengthWidth::Two, Endianness::Big) => {
                        u16::from_be_bytes([data[len_pos], data[len_pos + 1]]) as usize
                    }
                    (LengthWidth::Four, Endianness::Little) => {
                        u32::from_le_bytes([
                            data[len_pos],
                            data[len_pos + 1],
                            data[len_pos + 2],
                            data[len_pos + 3],
                        ]) as usize
                    }
                    (LengthWidth::Four, Endianness::Big) => {
                        u32::from_be_bytes([
                            data[len_pos],
                            data[len_pos + 1],
                            data[len_pos + 2],
                            data[len_pos + 3],
                        ]) as usize
                    }
                };

                let header_end = len_pos + (*width as usize);
                let message_end = header_end + len;

                if message_end > data.len() {
                    exceptions.push(format!("Message extends beyond PDU at pos {}", pos));
                    segments.push(Segment::new(
                        SegmentKind::Error("Message overflow".to_string()),
                        pos..data.len(),
                    ));
                    break;
                }

                if pos < header_end {
                    segments.push(Segment::new(
                        SegmentKind::Field("length".to_string()),
                        pos..header_end,
                    ));
                }

                if header_end < message_end {
                    segments.push(Segment::new(SegmentKind::Sdu, header_end..message_end));
                }

                if message_end < data.len() {
                    segments.push(Segment::new(
                        SegmentKind::MessageBoundary,
                        message_end..message_end,
                    ));
                }

                pos = message_end;
            }

            parsed_pdus.push(ParsedPdu { segments, exceptions });
        }

        ParsedCorpus::new(parsed_pdus)
    }
}

/// Parseur pour delimiter bundling
pub struct DelimiterParser;

impl Parser for DelimiterParser {
    fn name(&self) -> &'static str {
        "DelimiterParser"
    }

    fn applicable(&self, h: &Hypothesis) -> bool {
        matches!(h, Hypothesis::DelimiterBundle { .. })
    }

    fn parse_corpus(&self, corpus: &Corpus, h: &Hypothesis) -> ParsedCorpus {
        let Hypothesis::DelimiterBundle { pattern } = h else {
            return ParsedCorpus::new(vec![]);
        };

        let mut parsed_pdus = Vec::new();

        for pdu in &corpus.items {
            let data = pdu.as_slice();
            let mut segments = Vec::new();
            let mut pos = 0;
            let mut exceptions = Vec::new();

            while pos < data.len() {
                // Chercher le pattern
                let mut found = None;
                for i in pos..data.len().saturating_sub(pattern.len() - 1) {
                    if data[i..].starts_with(pattern) {
                        found = Some(i);
                        break;
                    }
                }

                let next_boundary = found.unwrap_or(data.len());
                if pos < next_boundary {
                    segments.push(Segment::new(SegmentKind::Sdu, pos..next_boundary));
                }

                if found.is_some() {
                    segments.push(Segment::new(
                        SegmentKind::MessageBoundary,
                        next_boundary..next_boundary + pattern.len(),
                    ));
                    pos = next_boundary + pattern.len();
                } else {
                    pos = data.len();
                }
            }

            parsed_pdus.push(ParsedPdu { segments, exceptions });
        }

        ParsedCorpus::new(parsed_pdus)
    }
}

/// Parseur pour fixed header
pub struct FixedHeaderParser;

impl Parser for FixedHeaderParser {
    fn name(&self) -> &'static str {
        "FixedHeaderParser"
    }

    fn applicable(&self, h: &Hypothesis) -> bool {
        matches!(h, Hypothesis::FixedHeader { .. })
    }

    fn parse_corpus(&self, corpus: &Corpus, h: &Hypothesis) -> ParsedCorpus {
        let Hypothesis::FixedHeader { len } = h else {
            return ParsedCorpus::new(vec![]);
        };

        let mut parsed_pdus = Vec::new();

        for pdu in &corpus.items {
            let data = pdu.as_slice();
            let mut segments = Vec::new();
            let mut exceptions = Vec::new();

            if data.len() < *len {
                segments.push(Segment::new(
                    SegmentKind::Error("PDU too short".to_string()),
                    0..data.len(),
                ));
            } else {
                segments.push(Segment::new(SegmentKind::Pci, 0..*len));
                if *len < data.len() {
                    segments.push(Segment::new(SegmentKind::Sdu, *len..data.len()));
                }
            }

            parsed_pdus.push(ParsedPdu { segments, exceptions });
        }

        ParsedCorpus::new(parsed_pdus)
    }
}

/// Parseur pour bitmap extensible
pub struct ExtensibleBitmapParser;

impl Parser for ExtensibleBitmapParser {
    fn name(&self) -> &'static str {
        "ExtensibleBitmapParser"
    }

    fn applicable(&self, h: &Hypothesis) -> bool {
        matches!(h, Hypothesis::ExtensibleBitmap { .. })
    }

    fn parse_corpus(&self, corpus: &Corpus, h: &Hypothesis) -> ParsedCorpus {
        let Hypothesis::ExtensibleBitmap {
            start,
            cont_bit,
            stop_value,
            max_bytes,
        } = h
        else {
            return ParsedCorpus::new(vec![]);
        };

        let mut parsed_pdus = Vec::new();

        for pdu in &corpus.items {
            let data = pdu.as_slice();
            let mut segments = Vec::new();
            let mut exceptions = Vec::new();

            if data.len() < *start {
                segments.push(Segment::new(
                    SegmentKind::Error("PDU too short for bitmap start".to_string()),
                    0..data.len(),
                ));
                parsed_pdus.push(ParsedPdu { segments, exceptions });
                continue;
            }

            // Lire la bitmap jusqu'à ce que le bit de continuation soit à stop_value
            let mut bitmap_pos = *start;
            let mut bitmap_len = 0;

            while bitmap_pos < data.len() && bitmap_len < *max_bytes {
                let byte = data[bitmap_pos];
                let cont_bit_value = (byte >> *cont_bit) & 1;
                bitmap_len += 1;

                if cont_bit_value == *stop_value {
                    break;
                }
                bitmap_pos += 1;
            }

            let bitmap_end = *start + bitmap_len;
            if bitmap_end > data.len() {
                exceptions.push("Bitmap extends beyond PDU".to_string());
                segments.push(Segment::new(
                    SegmentKind::Error("Bitmap overflow".to_string()),
                    0..data.len(),
                ));
            } else {
                if *start > 0 {
                    segments.push(Segment::new(SegmentKind::Pci, 0..*start));
                }
                segments.push(Segment::new(
                    SegmentKind::Field("bitmap".to_string()),
                    *start..bitmap_end,
                ));
                if bitmap_end < data.len() {
                    segments.push(Segment::new(SegmentKind::Sdu, bitmap_end..data.len()));
                }
            }

            parsed_pdus.push(ParsedPdu { segments, exceptions });
        }

        ParsedCorpus::new(parsed_pdus)
    }
}

/// Parseur pour TLV
pub struct TlvParser;

impl Parser for TlvParser {
    fn name(&self) -> &'static str {
        "TlvParser"
    }

    fn applicable(&self, h: &Hypothesis) -> bool {
        matches!(h, Hypothesis::Tlv { .. })
    }

    fn parse_corpus(&self, corpus: &Corpus, h: &Hypothesis) -> ParsedCorpus {
        let Hypothesis::Tlv { tag_offset, tag_bytes, len_offset, len_rule, length_includes_header } = h else {
            return ParsedCorpus::new(vec![]);
        };

        let mut parsed_pdus = Vec::new();

        for pdu in &corpus.items {
            let data = pdu.as_slice();
            let mut segments = Vec::new();
            let mut exceptions = Vec::new();
            let mut pos = 0;

            while pos < data.len() {
                // Vérifier qu'on a assez de place pour le tag à l'offset spécifié
                let tag_start = pos + *tag_offset;
                if tag_start + *tag_bytes > data.len() {
                    exceptions.push("Incomplete tag".to_string());
                    segments.push(Segment::new(
                        SegmentKind::Error("Incomplete tag".to_string()),
                        pos..data.len(),
                    ));
                    break;
                }

                // Ajouter un préfixe PCI si tag_offset > 0
                if *tag_offset > 0 && pos < tag_start {
                    segments.push(Segment::new(
                        SegmentKind::Pci,
                        pos..tag_start,
                    ));
                }

                // Tag
                segments.push(Segment::new(
                    SegmentKind::Field("tag".to_string()),
                    tag_start..tag_start + *tag_bytes,
                ));
                
                // Calculer où commence le length
                let length_start = pos + *len_offset;

                // Lire le length à l'offset spécifié
                let len = match len_rule {
                    TlvLenRule::DefiniteShort => {
                        if length_start >= data.len() {
                            exceptions.push("Incomplete length".to_string());
                            break;
                        }
                        let l = data[length_start] as usize;
                        l
                    }
                    TlvLenRule::DefiniteMedium => {
                        if length_start + 2 > data.len() {
                            exceptions.push("Incomplete length".to_string());
                            break;
                        }
                        // Network-friendly = Big Endian (standard pour les protocoles réseau)
                        // Always use big endian for network protocols
                        let l = u16::from_be_bytes([data[length_start], data[length_start + 1]]) as usize;
                        l
                    }
                    TlvLenRule::DefiniteLong => {
                        if length_start + 4 > data.len() {
                            exceptions.push("Incomplete length".to_string());
                            break;
                        }
                        let l = u32::from_be_bytes([
                            data[length_start],
                            data[length_start + 1],
                            data[length_start + 2],
                            data[length_start + 3],
                        ]) as usize;
                        l
                    }
                    TlvLenRule::IndefiniteWithEoc => {
                        // Chercher 0x00 0x00 à partir de length_start
                        let mut found = false;
                        let mut search_pos = length_start;
                        while search_pos + 1 < data.len() {
                            if data[search_pos] == 0x00 && data[search_pos + 1] == 0x00 {
                                found = true;
                                break;
                            }
                            search_pos += 1;
                        }
                        if !found {
                            exceptions.push("EOC not found".to_string());
                            break;
                        }
                        search_pos - length_start // Longueur jusqu'à EOC
                    }
                };
                
                let length_field_size = match len_rule {
                    TlvLenRule::DefiniteShort => 1,
                    TlvLenRule::DefiniteMedium => 2,
                    TlvLenRule::DefiniteLong => 4,
                    TlvLenRule::IndefiniteWithEoc => 0,
                };
                
                // Calculer où se termine le length field
                let length_end = length_start + length_field_size;
                
                // Ajouter un segment pour l'espace entre tag et length si nécessaire
                if tag_start + *tag_bytes < length_start {
                    segments.push(Segment::new(
                        SegmentKind::Pci,
                        tag_start + *tag_bytes..length_start,
                    ));
                }
                
                // Length field
                if length_field_size > 0 {
                    segments.push(Segment::new(
                        SegmentKind::Field("length".to_string()),
                        length_start..length_end,
                    ));
                }
                
                // Calculer où commence la valeur
                let value_start = length_end;
                
                // Détecter les length fields invalides (données corrompues, etc.)
                // Note: Le padding Ethernet est maintenant pré-filtré lors du chargement PCAP
                // 1. Length trop grand par rapport à ce qui reste dans le PDU
                let remaining_bytes = data.len().saturating_sub(value_start);
                if len > remaining_bytes + 1000 {
                    // Length absurde (plus de 1000 bytes au-delà de ce qui reste)
                    // Probablement des données corrompues ou un mauvais parsing
                    exceptions.push(format!("Length field appears invalid: len={}, remaining={}, stopping TLV parsing", len, remaining_bytes));
                    break;
                }
                
                // Utiliser length_includes_header comme spécifié dans l'hypothèse
                // Dans notre cas, length_includes_header = true (le length inclut le header)
                let header_size = length_end - tag_start;
                let actual_len = if *length_includes_header {
                    if len >= header_size {
                        len - header_size
                    } else {
                        // Length trop petit pour inclure le header
                        exceptions.push(format!("Length too small to include header: len={}, header_size={}", len, header_size));
                        break;
                    }
                } else {
                    len
                };

                // Vérifier que la valeur ne dépasse pas (déjà fait ci-dessus, mais double vérification)
                if value_start + actual_len > data.len() {
                    exceptions.push(format!("Value extends beyond PDU: value_start={}, actual_len={}, data_len={}, remaining={}", value_start, actual_len, data.len(), data.len() - value_start));
                    break;
                }
                
                // Vérifier aussi qu'on a assez de données restantes
                let remaining = data.len() - value_start;
                if actual_len > remaining {
                    exceptions.push(format!("Length too large for remaining data: actual_len={}, remaining={}", actual_len, remaining));
                    break;
                }

                // Ne pas créer de segment SDU si la longueur est 0
                if actual_len > 0 {
                    segments.push(Segment::new(SegmentKind::Sdu, value_start..value_start + actual_len));
                }
                
                // Avancer la position pour le prochain TLV
                if matches!(len_rule, TlvLenRule::IndefiniteWithEoc) {
                    // Pour IndefiniteWithEoc, chercher où se trouve EOC
                    let mut eoc_pos = length_start;
                    while eoc_pos + 1 < data.len() {
                        if data[eoc_pos] == 0x00 && data[eoc_pos + 1] == 0x00 {
                            pos = eoc_pos + 2; // Après EOC
                            break;
                        }
                        eoc_pos += 1;
                    }
                } else {
                    // Avancer la position pour le prochain TLV
                    if *length_includes_header {
                        // Si length inclut le header, avancer de 'len' depuis le début du tag
                        pos = tag_start + len;
                    } else {
                        // Sinon, avancer normalement
                        pos = value_start + actual_len;
                    }
                }
            }

            parsed_pdus.push(ParsedPdu { segments, exceptions });
        }

        ParsedCorpus::new(parsed_pdus)
    }
}

/// Parseur pour varint (protobuf-like)
pub struct VarintParser;

impl Parser for VarintParser {
    fn name(&self) -> &'static str {
        "VarintParser"
    }

    fn applicable(&self, h: &Hypothesis) -> bool {
        matches!(h, Hypothesis::VarintKeyWireType { .. })
    }

    fn parse_corpus(&self, corpus: &Corpus, h: &Hypothesis) -> ParsedCorpus {
        let Hypothesis::VarintKeyWireType {
            key_max_bytes,
            allow_embedded: _,
        } = h
        else {
            return ParsedCorpus::new(vec![]);
        };

        let mut parsed_pdus = Vec::new();

        for pdu in &corpus.items {
            let data = pdu.as_slice();
            let mut segments = Vec::new();
            let mut exceptions = Vec::new();
            let mut pos = 0;

            while pos < data.len() {
                // Lire la clé varint
                let mut key_bytes = 0;
                let mut key_value = 0u64;
                let mut key_start = pos;

                while key_bytes < *key_max_bytes && pos < data.len() {
                    let byte = data[pos];
                    key_value |= ((byte & 0x7F) as u64) << (key_bytes * 7);
                    key_bytes += 1;
                    pos += 1;

                    if (byte & 0x80) == 0 {
                        break;
                    }
                }

                if key_bytes >= *key_max_bytes && pos < data.len() && (data[pos - 1] & 0x80) != 0 {
                    exceptions.push("Varint key too long".to_string());
                    break;
                }

                segments.push(Segment::new(
                    SegmentKind::Field("key".to_string()),
                    key_start..pos,
                ));

                // Dériver le wire type (3 bits de poids faible)
                let wire_type = (key_value & 0x7) as u8;
                let field_number = (key_value >> 3) as u32;

                // Lire la valeur selon le wire type
                match wire_type {
                    0 => {
                        // Varint
                        let mut val_bytes = 0;
                        let val_start = pos;
                        while val_bytes < 10 && pos < data.len() {
                            let byte = data[pos];
                            val_bytes += 1;
                            pos += 1;
                            if (byte & 0x80) == 0 {
                                break;
                            }
                        }
                        segments.push(Segment::new(
                            SegmentKind::Field("value_varint".to_string()),
                            val_start..pos,
                        ));
                    }
                    1 => {
                        // Fixed64
                        if pos + 8 > data.len() {
                            exceptions.push("Incomplete fixed64".to_string());
                            break;
                        }
                        segments.push(Segment::new(
                            SegmentKind::Field("value_fixed64".to_string()),
                            pos..pos + 8,
                        ));
                        pos += 8;
                    }
                    2 => {
                        // Length-delimited
                        if pos >= data.len() {
                            exceptions.push("Incomplete length".to_string());
                            break;
                        }
                        let len = data[pos] as usize;
                        pos += 1;
                        if pos + len > data.len() {
                            exceptions.push("Length-delimited value extends beyond PDU".to_string());
                            break;
                        }
                        segments.push(Segment::new(
                            SegmentKind::Field("value_length".to_string()),
                            pos - 1..pos,
                        ));
                        segments.push(Segment::new(SegmentKind::Sdu, pos..pos + len));
                        pos += len;
                    }
                    5 => {
                        // Fixed32
                        if pos + 4 > data.len() {
                            exceptions.push("Incomplete fixed32".to_string());
                            break;
                        }
                        segments.push(Segment::new(
                            SegmentKind::Field("value_fixed32".to_string()),
                            pos..pos + 4,
                        ));
                        pos += 4;
                    }
                    _ => {
                        exceptions.push(format!("Unknown wire type: {}", wire_type));
                        break;
                    }
                }
            }

            parsed_pdus.push(ParsedPdu { segments, exceptions });
        }

        ParsedCorpus::new(parsed_pdus)
    }
}


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
        let Hypothesis::Tlv { tag_bytes, len_rule } = h else {
            return ParsedCorpus::new(vec![]);
        };

        let mut parsed_pdus = Vec::new();

        for pdu in &corpus.items {
            let data = pdu.as_slice();
            let mut segments = Vec::new();
            let mut exceptions = Vec::new();
            let mut pos = 0;

            while pos < data.len() {
                if pos + *tag_bytes > data.len() {
                    exceptions.push("Incomplete tag".to_string());
                    segments.push(Segment::new(
                        SegmentKind::Error("Incomplete tag".to_string()),
                        pos..data.len(),
                    ));
                    break;
                }

                segments.push(Segment::new(
                    SegmentKind::Field("tag".to_string()),
                    pos..pos + *tag_bytes,
                ));
                pos += *tag_bytes;

                let len = match len_rule {
                    TlvLenRule::DefiniteShort => {
                        if pos >= data.len() {
                            exceptions.push("Incomplete length".to_string());
                            break;
                        }
                        let l = data[pos] as usize;
                        pos += 1;
                        l
                    }
                    TlvLenRule::DefiniteLong => {
                        if pos + 4 > data.len() {
                            exceptions.push("Incomplete length".to_string());
                            break;
                        }
                        let l = u32::from_be_bytes([
                            data[pos],
                            data[pos + 1],
                            data[pos + 2],
                            data[pos + 3],
                        ]) as usize;
                        pos += 4;
                        l
                    }
                    TlvLenRule::IndefiniteWithEoc => {
                        // Chercher 0x00 0x00
                        let mut found = false;
                        let mut search_pos = pos;
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
                        let l = search_pos - pos;
                        pos = search_pos + 2;
                        l
                    }
                };

                segments.push(Segment::new(
                    SegmentKind::Field("length".to_string()),
                    pos - if matches!(len_rule, TlvLenRule::DefiniteShort) {
                        1
                    } else if matches!(len_rule, TlvLenRule::DefiniteLong) {
                        4
                    } else {
                        0
                    }..pos,
                ));

                if pos + len > data.len() {
                    exceptions.push("Value extends beyond PDU".to_string());
                    break;
                }

                segments.push(Segment::new(SegmentKind::Sdu, pos..pos + len));
                pos += len;
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


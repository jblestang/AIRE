#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::{Corpus, CorpusMeta, PduRef};
    use crate::hypothesis::{Endianness, Hypothesis, LengthWidth, TlvLenRule};
    use crate::inference::InferenceEngine;
    use crate::parser::Parser;
    use crate::plugins::*;
    use crate::plugin::PluginRegistry;
    use crate::segment::SegmentKind;
    use std::sync::Arc;

    fn create_test_corpus(data: Vec<Vec<u8>>) -> Corpus {
        let items: Vec<PduRef> = data
            .into_iter()
            .map(|bytes| {
                let len = bytes.len();
                PduRef::new(Arc::from(bytes), 0..len)
            })
            .collect();

        let pdu_count = items.len();
        let total_bytes: usize = items.iter().map(|p| p.len()).sum();

        Corpus::new(
            items,
            CorpusMeta {
                source: "test".to_string(),
                total_bytes,
                pdu_count,
                flow_id: None,
            },
        )
    }

    #[test]
    fn test_length_prefix_bundling() {
        // Créer un corpus avec length-prefix bundling (little-endian, 2 bytes)
        let mut data = Vec::new();
        for i in 0..5 {
            let payload: Vec<u8> = vec![i as u8; 10 + i]; // Payloads de taille variable
            let len = payload.len() as u16;
            let mut pdu = len.to_le_bytes().to_vec();
            pdu.extend_from_slice(&payload);
            data.push(pdu);
        }

        let corpus = create_test_corpus(data);
        let registry = create_default_registry();

        // Trouver le parseur length-prefix
        let hypothesis = Hypothesis::LengthPrefixBundle {
            offset: 0,
            width: LengthWidth::Two,
            endian: Endianness::Little,
            includes_header: false,
        };

        let parser = registry
            .parsers()
            .iter()
            .find(|p| p.applicable(&hypothesis))
            .expect("Parser length-prefix devrait être disponible");

        let parsed = parser.parse_corpus(&corpus, &hypothesis);
        assert!(parsed.parse_success_ratio() >= 0.95);

        // Vérifier que chaque PDU a été correctement segmenté
        for parsed_pdu in &parsed.parsed_pdus {
            assert!(parsed_pdu.is_success());
            assert!(parsed_pdu.segments.len() >= 2); // Au moins length + SDU
        }
    }

    #[test]
    fn test_fixed_header() {
        // Créer un corpus avec header fixe de 4 octets
        let mut data = Vec::new();
        for i in 0..5 {
            let mut pdu = vec![0x01, 0x02, 0x03, 0x04]; // Header fixe
            let payload: Vec<u8> = vec![i as u8; 20]; // Payload
            pdu.extend_from_slice(&payload);
            data.push(pdu);
        }

        let corpus = create_test_corpus(data);
        let registry = create_default_registry();

        let hypothesis = Hypothesis::FixedHeader { len: 4 };

        let parser = registry
            .parsers()
            .iter()
            .find(|p| p.applicable(&hypothesis))
            .expect("Parser fixed-header devrait être disponible");

        let parsed = parser.parse_corpus(&corpus, &hypothesis);
        assert!(parsed.parse_success_ratio() >= 0.95);

        for parsed_pdu in &parsed.parsed_pdus {
            assert!(parsed_pdu.is_success());
            assert_eq!(parsed_pdu.segments[0].kind, SegmentKind::Pci);
            assert_eq!(parsed_pdu.segments[0].len(), 4);
        }
    }

    #[test]
    fn test_extensible_bitmap() {
        // Créer un corpus avec bitmap extensible
        // Bitmap: continuation bit = bit 7, stop quand bit 7 = 0
        let mut data = Vec::new();
        for _ in 0..5 {
            let mut pdu = vec![0x80, 0x80, 0x00]; // Bitmap: continue, continue, stop
            let payload: Vec<u8> = vec![0xAA; 20]; // Payload
            pdu.extend_from_slice(&payload);
            data.push(pdu);
        }

        let corpus = create_test_corpus(data);
        let registry = create_default_registry();

        let hypothesis = Hypothesis::ExtensibleBitmap {
            start: 0,
            cont_bit: 7,
            stop_value: 0,
            max_bytes: 8,
        };

        let parser = registry
            .parsers()
            .iter()
            .find(|p| p.applicable(&hypothesis))
            .expect("Parser bitmap devrait être disponible");

        let parsed = parser.parse_corpus(&corpus, &hypothesis);
        assert!(parsed.parse_success_ratio() >= 0.95);

        for parsed_pdu in &parsed.parsed_pdus {
            assert!(parsed_pdu.is_success());
            // Devrait avoir au moins un segment bitmap
            assert!(parsed_pdu
                .segments
                .iter()
                .any(|s| matches!(s.kind, SegmentKind::Field(ref name) if name == "bitmap")));
        }
    }

    #[test]
    fn test_tlv_definite_short() {
        // Créer un corpus avec TLV (tag=1 byte, length=1 byte)
        let mut data = Vec::new();
        for i in 0..5 {
            let mut pdu = vec![0x01]; // Tag
            pdu.push(10); // Length
            let value: Vec<u8> = vec![i as u8; 10]; // Value
            pdu.extend_from_slice(&value);
            data.push(pdu);
        }

        let corpus = create_test_corpus(data);
        let registry = create_default_registry();

        let hypothesis = Hypothesis::Tlv {
            tag_offset: 0,
            tag_bytes: 1,
            len_offset: 1,
            len_rule: TlvLenRule::DefiniteShort,
            length_includes_header: false,
        };

        let parser = registry
            .parsers()
            .iter()
            .find(|p| p.applicable(&hypothesis))
            .expect("Parser TLV devrait être disponible");

        let parsed = parser.parse_corpus(&corpus, &hypothesis);
        assert!(parsed.parse_success_ratio() >= 0.95);

        for parsed_pdu in &parsed.parsed_pdus {
            assert!(parsed_pdu.is_success());
            // Devrait avoir tag, length, et value
            assert!(parsed_pdu.segments.len() >= 3);
        }
    }

    #[test]
    fn test_varint_protobuf_like() {
        // Créer un corpus avec varint (protobuf-like)
        // Key: field_number=1, wire_type=2 (length-delimited)
        let mut data = Vec::new();
        for i in 0..5 {
            let mut pdu = vec![0x0A]; // Key: field 1, wire_type 2
            pdu.push(10); // Length
            let value: Vec<u8> = vec![i as u8; 10]; // Value
            pdu.extend_from_slice(&value);
            data.push(pdu);
        }

        let corpus = create_test_corpus(data);
        let registry = create_default_registry();

        let hypothesis = Hypothesis::VarintKeyWireType {
            key_max_bytes: 5,
            allow_embedded: false,
        };

        let parser = registry
            .parsers()
            .iter()
            .find(|p| p.applicable(&hypothesis))
            .expect("Parser varint devrait être disponible");

        let parsed = parser.parse_corpus(&corpus, &hypothesis);
        // Varint peut être plus tolérant aux erreurs
        assert!(parsed.parse_success_ratio() >= 0.8);

        for parsed_pdu in &parsed.parsed_pdus {
            // Au moins une clé devrait être parsée
            assert!(parsed_pdu.segments.len() >= 1);
        }
    }

    #[test]
    fn test_inference_engine_length_prefix() {
        // Test que le moteur d'inférence choisit correctement length-prefix
        let mut data = Vec::new();
        for i in 0..10 {
            let payload: Vec<u8> = vec![i as u8; 10 + i];
            let len = payload.len() as u16;
            let mut pdu = len.to_le_bytes().to_vec();
            pdu.extend_from_slice(&payload);
            data.push(pdu);
        }

        let corpus = create_test_corpus(data);
        let registry = create_default_registry();
        let engine = InferenceEngine::new().with_max_depth(3);

        let result = engine.infer(corpus, &registry);

        // Devrait trouver au moins une couche
        assert!(!result.layers.is_empty());

        // La première couche devrait être length-prefix ou avoir un bon score
        let first_layer = &result.layers[0];
        assert!(first_layer.score.breakdown.parse_success_ratio >= 0.95);
    }
}


use crate::corpus::Corpus;
use crate::hypothesis::Hypothesis;
use crate::measures::{compressed_size, entropy};
use crate::parser::ParsedCorpus;
use crate::plugin::Scorer;
use crate::score::{Score, ScoreBreakdown};

/// Scoreur MDL standard
pub struct MdlScorer {
    pub min_parse_success_ratio: f64,
}

impl MdlScorer {
    pub fn new() -> Self {
        Self {
            min_parse_success_ratio: 0.95,
        }
    }
}

impl Default for MdlScorer {
    fn default() -> Self {
        Self::new()
    }
}

impl Scorer for MdlScorer {
    fn name(&self) -> &'static str {
        "MdlScorer"
    }

    fn score(
        &self,
        corpus: &Corpus,
        parsed: &ParsedCorpus,
        h: &Hypothesis,
    ) -> Score {
        // Vérifier les exceptions "extends beyond PDU" - éliminateurs
        // Ces exceptions indiquent que l'hypothèse ne peut pas parser correctement les données
        let has_pdu_overflow_exceptions = parsed.parsed_pdus.iter().any(|p| {
            p.exceptions.iter().any(|exc| {
                exc.contains("extends beyond PDU") || 
                exc.contains("Length too large for remaining data") ||
                exc.contains("Message extends beyond PDU") ||
                exc.contains("Bitmap extends beyond PDU") ||
                exc.contains("Length-delimited value extends beyond PDU")
            })
        });

        // Si des exceptions "extends beyond PDU" existent, rejeter l'hypothèse
        if has_pdu_overflow_exceptions {
            // Log pour debug
            if let Hypothesis::Tlv { tag_bytes, len_rule, len_offset, length_includes_header, .. } = h {
                if *tag_bytes == 1 && matches!(len_rule, crate::hypothesis::TlvLenRule::DefiniteMedium) {
                    let exception_count: usize = parsed.parsed_pdus.iter()
                        .map(|p| p.exceptions.len())
                        .sum();
                    tracing::info!(
                        "REJET: TLV Tag={} Len=2 (offset: tag={}, len={}, includes_header={}) a des exceptions 'extends beyond PDU' ({} exceptions totales)",
                        tag_bytes, 0, len_offset, length_includes_header, exception_count
                    );
                }
            }
            return Score::new(ScoreBreakdown {
                mdl_model_bits: f64::INFINITY,
                mdl_data_bits: f64::INFINITY,
                parse_success_ratio: 0.0,
                alignment_gain_bits: 0.0,
                entropy_drop_bits: 0.0,
                penalties_bits: f64::INFINITY,
            });
        }

        let parse_success_ratio = parsed.parse_success_ratio();

        // Contrainte dure : PSR doit être >= seuil
        if parse_success_ratio < self.min_parse_success_ratio {
            return Score::new(ScoreBreakdown {
                mdl_model_bits: f64::INFINITY,
                mdl_data_bits: f64::INFINITY,
                parse_success_ratio,
                alignment_gain_bits: 0.0,
                entropy_drop_bits: 0.0,
                penalties_bits: f64::INFINITY,
            });
        }

        // Extraire les données (PCI, Fields, SDU) pour les calculs MDL
        let mut pci_data = Vec::new();
        let mut sdu_data = Vec::new();
        let mut field_data = Vec::new();
        let mut total_pci_bytes = 0;
        let mut total_sdu_bytes = 0;
        let mut _total_field_bytes = 0;

        for (pdu, parsed_pdu) in corpus.items.iter().zip(parsed.parsed_pdus.iter()) {
            for segment in &parsed_pdu.segments {
                let slice = &pdu.as_slice()[segment.range.clone()];
                match segment.kind {
                    crate::segment::SegmentKind::Pci => {
                        pci_data.extend_from_slice(slice);
                        total_pci_bytes += slice.len();
                    }
                    crate::segment::SegmentKind::Sdu => {
                        sdu_data.extend_from_slice(slice);
                        total_sdu_bytes += slice.len();
                    }
                    crate::segment::SegmentKind::Field(_) => {
                        field_data.extend_from_slice(slice);
                        _total_field_bytes += slice.len();
                    }
                    _ => {
                        // Ignorer les autres types (Error, MessageBoundary, etc.)
                    }
                }
            }
        }

        // MDL Model : complexité de l'hypothèse
        // Inclut aussi les bits pour encoder les PCI et Fields (métadonnées du modèle)
        let mdl_model_bits = {
            let base_model_bits = estimate_model_bits(h);
            
            // Ajouter les bits pour encoder les PCI et Fields (métadonnées)
            let pci_bits = if !pci_data.is_empty() {
                let pci_entropy = entropy(&pci_data);
                let pci_compressed = compressed_size(&pci_data).map(|s| s as f64 * 8.0).unwrap_or(pci_entropy * pci_data.len() as f64);
                (pci_entropy * pci_data.len() as f64).min(pci_compressed)
            } else {
                0.0
            };
            
            let field_bits = if !field_data.is_empty() {
                let field_entropy = entropy(&field_data);
                let field_compressed = compressed_size(&field_data).map(|s| s as f64 * 8.0).unwrap_or(field_entropy * field_data.len() as f64);
                (field_entropy * field_data.len() as f64).min(field_compressed)
            } else {
                0.0
            };
            
            base_model_bits + pci_bits + field_bits
        };

        // MDL Data : bits pour encoder les données selon le modèle
        // MDL(Data|Model) = bits(SDU) seulement
        // Les SDUs sont les données réellement "expliquées" par le modèle
        // Les PCI et Fields sont des métadonnées qui font partie du modèle (MDL Model)
        // IMPORTANT: Normaliser par le nombre de bytes de SDUs pour comparer équitablement
        // Si une hypothèse extrait 6522 bytes de SDUs et une autre 1000 bytes,
        // on compare le coût par byte de SDU

        // Calculer les bits pour encoder les SDUs selon le modèle
        // MDL(Data|Model) = bits(SDU) - PAS de normalisation
        // Si une hypothèse extrait plus de SDUs, elle a besoin de plus de bits, c'est normal
        // Le gain d'entropie (entropy_drop) devrait compenser si les SDUs sont bien structurés
        let mdl_data_bits = {
            if !sdu_data.is_empty() {
                // Les SDUs sont les données réellement "expliquées" par le modèle
                // Ils devraient être bien compressibles si le modèle est bon
                let sdu_entropy = entropy(&sdu_data);
                let sdu_compressed = compressed_size(&sdu_data).map(|s| s as f64 * 8.0).unwrap_or(sdu_entropy * sdu_data.len() as f64);
                // Prendre le minimum entre entropie et compression
                (sdu_entropy * sdu_data.len() as f64).min(sdu_compressed)
            } else {
                // Pas de SDUs extraits = pénalité maximale
                corpus.total_bytes() as f64 * 8.0
            }
        };

        // Pénalités
        let mut penalties_bits = 0.0;

        // Pénalité pour sur-découpage (trop de segments)
        let avg_segments = parsed
            .parsed_pdus
            .iter()
            .map(|p| p.segments.len())
            .sum::<usize>() as f64
            / parsed.parsed_pdus.len().max(1) as f64;

        if avg_segments > 10.0 {
            penalties_bits += (avg_segments - 10.0) * 8.0;
        }

        // Pénalité pour exceptions
        // Note: Le padding Ethernet est maintenant pré-filtré lors du chargement PCAP
        // Donc on pénalise toutes les exceptions restantes
        let exception_count: usize = parsed
            .parsed_pdus
            .iter()
            .map(|p| p.exceptions.len())
            .sum();
        penalties_bits += exception_count as f64 * 16.0;

        // Pénalité pour segments trop petits
        let small_segments = parsed
            .parsed_pdus
            .iter()
            .flat_map(|p| &p.segments)
            .filter(|s| s.len() < 2)
            .count();
        penalties_bits += small_segments as f64 * 4.0;

        // Pénalité pour utilisation de little endian (non network-friendly)
        // Les protocoles réseau utilisent généralement big endian
        // Note: Cette pénalité est implicite car nous utilisons toujours big endian dans le parser
        // Mais on peut pénaliser les hypothèses qui nécessiteraient little endian pour fonctionner

        // Calculer le gain d'entropie : comparaison avec les données brutes
        // On compare la compressibilité des données brutes avec les données selon le modèle
        // Le gain mesure la réduction d'entropie obtenue en structurant les données
        // On inclut PCI + Fields + SDU car ce sont toutes les données selon le modèle
        let entropy_drop_bits = {
            // Calculer l'entropie/compression des données brutes
            let raw_data: Vec<u8> = corpus.items.iter()
                .flat_map(|p| p.as_slice())
                .copied()
                .collect();
            
            if raw_data.is_empty() {
                0.0
            } else {
                // Calculer la taille compressée de chaque composant du modèle
                let pci_compressed = if !pci_data.is_empty() {
                    compressed_size(&pci_data).map(|s| s as f64 * 8.0).unwrap_or_else(|_| {
                        let pci_entropy = entropy(&pci_data);
                        pci_entropy * pci_data.len() as f64
                    })
                } else {
                    0.0
                };
                
                let field_compressed = if !field_data.is_empty() {
                    compressed_size(&field_data).map(|s| s as f64 * 8.0).unwrap_or_else(|_| {
                        let field_entropy = entropy(&field_data);
                        field_entropy * field_data.len() as f64
                    })
                } else {
                    0.0
                };
                
                let sdu_compressed = if !sdu_data.is_empty() {
                    compressed_size(&sdu_data).map(|s| s as f64 * 8.0).unwrap_or_else(|_| {
                        let sdu_entropy = entropy(&sdu_data);
                        sdu_entropy * sdu_data.len() as f64
                    })
                } else {
                    0.0
                };
                
                // Taille compressée totale selon le modèle
                let model_compressed = pci_compressed + field_compressed + sdu_compressed;
                
                // Taille compressée des données brutes
                let raw_compressed = compressed_size(&raw_data).map(|s| s as f64 * 8.0).unwrap_or_else(|_| {
                    let raw_entropy = entropy(&raw_data);
                    raw_entropy * raw_data.len() as f64
                });
                
                // Le gain = réduction de taille compressée
                // Si les données selon le modèle sont plus compressibles que les données brutes, on gagne
                if model_compressed < raw_compressed {
                    let gain = raw_compressed - model_compressed;
                    gain.max(0.0)
                } else {
                    0.0
                }
            }
        };

        // Log pour debug si c'est une hypothèse Tag=1, Len=2
        if let Hypothesis::Tlv { tag_bytes, len_rule, len_offset, length_includes_header, .. } = h {
            if *tag_bytes == 1 && matches!(len_rule, crate::hypothesis::TlvLenRule::DefiniteMedium) && *len_offset == 1 && *length_includes_header {
                let raw_data: Vec<u8> = corpus.items.iter().flat_map(|p| p.as_slice()).copied().collect();
                let raw_compressed = compressed_size(&raw_data).map(|s| s as f64 * 8.0).unwrap_or(0.0);
                
                // Calculer les tailles compressées séparément (comme dans entropy_drop)
                let pci_compressed = if !pci_data.is_empty() {
                    compressed_size(&pci_data).map(|s| s as f64 * 8.0).unwrap_or(0.0)
                } else {
                    0.0
                };
                
                let field_compressed = if !field_data.is_empty() {
                    compressed_size(&field_data).map(|s| s as f64 * 8.0).unwrap_or(0.0)
                } else {
                    0.0
                };
                
                let sdu_compressed = if !sdu_data.is_empty() {
                    compressed_size(&sdu_data).map(|s| s as f64 * 8.0).unwrap_or(0.0)
                } else {
                    0.0
                };
                
                let model_compressed = pci_compressed + field_compressed + sdu_compressed;
                
                let raw_ratio = if raw_data.len() > 0 { raw_compressed / raw_data.len() as f64 } else { 0.0 };
                let sdu_ratio = if sdu_data.len() > 0 { sdu_compressed / sdu_data.len() as f64 } else { 0.0 };
                let model_ratio = if (pci_data.len() + field_data.len() + sdu_data.len()) > 0 {
                    model_compressed / (pci_data.len() + field_data.len() + sdu_data.len()) as f64
                } else {
                    0.0
                };
                
                tracing::info!(
                    "Tag=1 Len=2 includes_header=true: mdl_data={:.2}, entropy_drop={:.2}, raw_compressed={:.2} (ratio={:.3}), pci_compressed={:.2}, field_compressed={:.2}, sdu_compressed={:.2} (ratio={:.3}), model_compressed={:.2} (ratio={:.3}), pci_bytes={}, field_bytes={}, sdu_bytes={}, total_bytes={}",
                    mdl_data_bits,
                    entropy_drop_bits,
                    raw_compressed,
                    raw_ratio,
                    pci_compressed,
                    field_compressed,
                    sdu_compressed,
                    sdu_ratio,
                    model_compressed,
                    model_ratio,
                    pci_data.len(),
                    field_data.len(),
                    sdu_data.len(),
                    raw_data.len()
                );
            }
        }

        Score::new(ScoreBreakdown {
            mdl_model_bits,
            mdl_data_bits,
            parse_success_ratio,
            alignment_gain_bits: 0.0, // TODO: calculer si nécessaire (pour ExtensibleBitmap)
            entropy_drop_bits,
            penalties_bits,
        })
    }
}

/// Estime les bits nécessaires pour encoder le modèle
fn estimate_model_bits(h: &Hypothesis) -> f64 {
    match h {
        Hypothesis::LengthPrefixBundle { .. } => 32.0,
        Hypothesis::DelimiterBundle { pattern } => 16.0 + pattern.len() as f64 * 8.0,
        Hypothesis::FixedHeader { len } => 16.0 + (*len as f64).log2() * 2.0,
        Hypothesis::ExtensibleBitmap { .. } => 40.0,
        Hypothesis::Tlv { .. } => 24.0,
        Hypothesis::VarintKeyWireType { .. } => 24.0,
    }
}


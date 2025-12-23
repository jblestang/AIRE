use crate::corpus::{Corpus, PduRef};
use crate::hypothesis::Hypothesis;
use crate::parser::ParsedCorpus;
use crate::plugin::PluginRegistry;
use crate::score::Score;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

/// Résultat d'une couche d'inférence
#[derive(Debug, Clone)]
pub struct Layer {
    pub hypothesis: Hypothesis,
    pub score: Score,
    pub parsed: ParsedCorpus,
    pub sdu_corpus: Option<Corpus>,
}

// Implémentation manuelle de Serialize pour Layer
impl serde::Serialize for Layer {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("Layer", 4)?;
        state.serialize_field("hypothesis", &self.hypothesis)?;
        state.serialize_field("score", &self.score)?;
        // Note: ParsedCorpus et Corpus ne sont pas sérialisés ici pour simplifier
        // Dans une vraie implémentation, créer des structures sérialisables dédiées
        state.serialize_field("parsed_pdu_count", &self.parsed.parsed_pdus.len())?;
        state.serialize_field("has_sdu_corpus", &self.sdu_corpus.is_some())?;
        state.end()
    }
}

/// Résultat complet de l'inférence
#[derive(Debug, Clone)]
pub struct InferenceResult {
    pub layers: Vec<Layer>,
    pub corpus: Corpus,
}

// Implémentation manuelle de Serialize pour InferenceResult
impl serde::Serialize for InferenceResult {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("InferenceResult", 2)?;
        state.serialize_field("layers", &self.layers)?;
        state.serialize_field("corpus_pdu_count", &self.corpus.len())?;
        state.serialize_field("corpus_total_bytes", &self.corpus.total_bytes())?;
        state.end()
    }
}

/// Moteur d'inférence récursive
pub struct InferenceEngine {
    pub max_depth: usize,
    pub top_k: usize,
    pub min_gain_epsilon: f64,
    pub min_sdu_size: usize,
}

impl InferenceEngine {
    pub fn new() -> Self {
        Self {
            max_depth: 6,
            top_k: 10,
            min_gain_epsilon: 100.0, // bits
            min_sdu_size: 4,
        }
    }

    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    pub fn with_top_k(mut self, k: usize) -> Self {
        self.top_k = k;
        self
    }

    /// Infère la structure du protocole de manière récursive
    pub fn infer(
        &self,
        corpus: Corpus,
        registry: &PluginRegistry,
    ) -> InferenceResult {
        let mut layers = Vec::new();
        let mut current_corpus = corpus.clone();

        for depth in 0..self.max_depth {
            if current_corpus.is_empty() {
                break;
            }

            // Vérifier la taille minimale
            let avg_size: f64 = current_corpus
                .items
                .iter()
                .map(|p| p.len())
                .sum::<usize>() as f64
                / current_corpus.items.len().max(1) as f64;

            if avg_size < self.min_sdu_size as f64 {
                break;
            }

            // Générer toutes les hypothèses
            let mut hypotheses = Vec::new();
            for generator in registry.generators() {
                hypotheses.extend(generator.propose(&current_corpus));
            }

            if hypotheses.is_empty() {
                break;
            }

            // Parser et scorer toutes les hypothèses (parallèle)
            let scored: Vec<(Hypothesis, Score, ParsedCorpus)> = hypotheses
                .into_par_iter()
                .filter_map(|h| {
                    // Trouver un parseur applicable
                    let parser = registry.parsers().iter().find(|p| p.applicable(&h))?;

                    // Parser
                    let parsed = parser.parse_corpus(&current_corpus, &h);

                    // Trouver un scoreur
                    let scorer = registry.scorers().first()?;

                    // Scorer
                    let score = scorer.score(&current_corpus, &parsed, &h);

                    Some((h, score, parsed))
                })
                .collect();

            if scored.is_empty() {
                break;
            }

            // Trier par score (min = meilleur)
            let mut sorted: Vec<_> = scored.into_iter().collect();
            sorted.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

            // Garder top-K
            let top_k_results: Vec<_> = sorted
                .into_iter()
                .take(self.top_k)
                .collect();

            if top_k_results.is_empty() {
                break;
            }

            // Choisir le meilleur
            let (best_hypothesis, best_score, best_parsed) = top_k_results[0].clone();

            // Vérifier le gain vs "raw" (pas de parsing)
            let raw_score = self.raw_score(&current_corpus);
            let gain = raw_score.total_bits - best_score.total_bits;

            if gain < self.min_gain_epsilon {
                // Pas assez de gain, arrêter
                break;
            }

            // Extraire le corpus SDU pour la récursion
            let sdu_corpus = self.extract_sdu_corpus(&current_corpus, &best_parsed);

            layers.push(Layer {
                hypothesis: best_hypothesis,
                score: best_score,
                parsed: best_parsed,
                sdu_corpus: sdu_corpus.clone(),
            });

            // Continuer avec le SDU corpus
            if let Some(sdu_corpus) = sdu_corpus {
                current_corpus = sdu_corpus;
            } else {
                break;
            }
        }

        InferenceResult {
            layers,
            corpus,
        }
    }

    /// Score pour un corpus "raw" (sans parsing)
    fn raw_score(&self, corpus: &Corpus) -> Score {
        use crate::measures::compressed_size;
        use crate::score::ScoreBreakdown;

        let total_bits = match compressed_size(
            &corpus
                .items
                .iter()
                .flat_map(|p| p.as_slice())
                .copied()
                .collect::<Vec<_>>(),
        ) {
            Ok(size) => size as f64 * 8.0,
            Err(_) => corpus.total_bytes() as f64 * 8.0,
        };

        Score::new(ScoreBreakdown {
            mdl_model_bits: 0.0,
            mdl_data_bits: total_bits,
            parse_success_ratio: 1.0,
            alignment_gain_bits: 0.0,
            entropy_drop_bits: 0.0,
            penalties_bits: 0.0,
        })
    }

    /// Extrait un nouveau corpus à partir des SDUs parsés
    fn extract_sdu_corpus(
        &self,
        corpus: &Corpus,
        parsed: &ParsedCorpus,
    ) -> Option<Corpus> {
        let mut sdu_items = Vec::new();

        for (pdu, parsed_pdu) in corpus.items.iter().zip(parsed.parsed_pdus.iter()) {
            for segment in &parsed_pdu.segments {
                if matches!(segment.kind, crate::segment::SegmentKind::Sdu) {
                    let sdu_data = &pdu.as_slice()[segment.range.clone()];
                    if sdu_data.len() >= self.min_sdu_size {
                        sdu_items.push(PduRef::new(
                            pdu.data.clone(),
                            segment.range.clone(),
                        ));
                    }
                }
            }
        }

        if sdu_items.is_empty() {
            return None;
        }

        let pdu_count = sdu_items.len();
        let total_bytes: usize = sdu_items.iter().map(|p| p.len()).sum();

        Some(Corpus::new(
            sdu_items,
            crate::corpus::CorpusMeta {
                source: format!("{}_sdu", corpus.meta.source),
                total_bytes,
                pdu_count,
                flow_id: corpus.meta.flow_id,
            },
        ))
    }
}

impl Default for InferenceEngine {
    fn default() -> Self {
        Self::new()
    }
}


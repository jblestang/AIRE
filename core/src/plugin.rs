use crate::{corpus::Corpus, hypothesis::Hypothesis, parser::ParsedCorpus, score::Score};

/// Générateur d'hypothèses
pub trait HypothesisGenerator: Send + Sync {
    fn name(&self) -> &'static str;
    fn propose(&self, corpus: &Corpus) -> Vec<Hypothesis>;
}

/// Scoreur d'hypothèses
pub trait Scorer: Send + Sync {
    fn name(&self) -> &'static str;
    fn score(
        &self,
        corpus: &Corpus,
        parsed: &ParsedCorpus,
        h: &Hypothesis,
    ) -> Score;
}

/// Registre de plugins
pub struct PluginRegistry {
    generators: Vec<Box<dyn HypothesisGenerator>>,
    parsers: Vec<Box<dyn crate::parser::Parser>>,
    scorers: Vec<Box<dyn Scorer>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            generators: Vec::new(),
            parsers: Vec::new(),
            scorers: Vec::new(),
        }
    }

    pub fn register_generator(&mut self, gen: Box<dyn HypothesisGenerator>) {
        self.generators.push(gen);
    }

    pub fn register_parser(&mut self, parser: Box<dyn crate::parser::Parser>) {
        self.parsers.push(parser);
    }

    pub fn register_scorer(&mut self, scorer: Box<dyn Scorer>) {
        self.scorers.push(scorer);
    }

    pub fn generators(&self) -> &[Box<dyn HypothesisGenerator>] {
        &self.generators
    }

    pub fn parsers(&self) -> &[Box<dyn crate::parser::Parser>] {
        &self.parsers
    }

    pub fn scorers(&self) -> &[Box<dyn Scorer>] {
        &self.scorers
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}


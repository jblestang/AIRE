pub mod generators;
pub mod parsers;
pub mod scorers;

pub use generators::*;
pub use parsers::*;
pub use scorers::*;

use crate::plugin::PluginRegistry;

/// Crée un registre de plugins avec tous les plugins par défaut
pub fn create_default_registry() -> PluginRegistry {
    let mut registry = PluginRegistry::new();

    // Enregistrer les générateurs
    registry.register_generator(Box::new(LengthPrefixGenerator));
    registry.register_generator(Box::new(DelimiterGenerator));
    registry.register_generator(Box::new(FixedHeaderGenerator));
    registry.register_generator(Box::new(ExtensibleBitmapGenerator));
    registry.register_generator(Box::new(TlvGenerator));
    registry.register_generator(Box::new(VarintGenerator));

    // Enregistrer les parseurs
    registry.register_parser(Box::new(LengthPrefixParser));
    registry.register_parser(Box::new(DelimiterParser));
    registry.register_parser(Box::new(FixedHeaderParser));
    registry.register_parser(Box::new(ExtensibleBitmapParser));
    registry.register_parser(Box::new(TlvParser));
    registry.register_parser(Box::new(VarintParser));

    // Enregistrer les scoreurs
    registry.register_scorer(Box::new(MdlScorer::new()));

    registry
}

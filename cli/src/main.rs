use anyhow::{Context, Result};
use clap::Parser;
use protocol_infer_core::{
    pcap, plugins, Corpus, InferenceEngine, PluginRegistry,
};
use serde_json;
use std::fs;
use tracing::{info, Level};
use tracing_subscriber;

#[derive(Parser)]
#[command(name = "protocol_infer")]
#[command(about = "Infère automatiquement la structure d'un protocole à partir d'un fichier PCAP")]
struct Args {
    /// Fichier PCAP à analyser
    #[arg(short, long)]
    pcap: String,

    /// Fichier de sortie JSON
    #[arg(short, long)]
    out: String,


    /// Profondeur maximale de récursion
    #[arg(long, default_value = "6")]
    max_depth: usize,

    /// Nombre d'hypothèses top-K à garder par couche
    #[arg(long, default_value = "10")]
    top_k: usize,
}

fn main() -> Result<()> {
    // Initialiser le logging
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    let args = Args::parse();

    info!("Chargement du fichier PCAP: {}", args.pcap);
    let flow = pcap::parse_pcap(&args.pcap)
        .with_context(|| format!("Échec du parsing PCAP: {}", args.pcap))?;

    info!("{} paquets UDP trouvés", flow.datagrams.len());

    if flow.datagrams.is_empty() {
        anyhow::bail!("Aucun paquet UDP trouvé dans le fichier PCAP");
    }

    let registry = plugins::create_default_registry();
    let engine = InferenceEngine::new()
        .with_max_depth(args.max_depth)
        .with_top_k(args.top_k);

    info!("Traitement de {} datagrammes", flow.datagrams.len());

    let corpus = Corpus::from_datagrams(&flow.datagrams, Some(0));
    info!("Corpus créé: {} PDUs, {} octets", corpus.len(), corpus.total_bytes());

    let result = engine.infer(corpus, &registry);
    info!("Inférence terminée: {} couches trouvées", result.layers.len());

    let output = serde_json::json!({
        "flow": flow,
        "result": result,
        "summary": {
            "total_packets": flow.datagrams.len(),
        }
    });

    fs::write(&args.out, serde_json::to_string_pretty(&output)?)
        .with_context(|| format!("Échec de l'écriture du fichier: {}", args.out))?;

    info!("Résultats sauvegardés dans: {}", args.out);

    Ok(())
}


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

    /// Index du flow à analyser (optionnel, analyse tous les flows par défaut)
    #[arg(short, long)]
    flow: Option<usize>,

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
    let flows = pcap::parse_pcap(&args.pcap)
        .with_context(|| format!("Échec du parsing PCAP: {}", args.pcap))?;

    info!("{} flows UDP trouvés", flows.len());

    let flows_to_process = if let Some(flow_idx) = args.flow {
        if flow_idx >= flows.len() {
            anyhow::bail!("Index de flow invalide: {} (max: {})", flow_idx, flows.len() - 1);
        }
        vec![flows[flow_idx].clone()]
    } else {
        flows
    };

    let registry = plugins::create_default_registry();
    let engine = InferenceEngine::new()
        .with_max_depth(args.max_depth)
        .with_top_k(args.top_k);

    let mut results = Vec::new();

    for (idx, flow) in flows_to_process.iter().enumerate() {
        info!("Traitement du flow {} ({} datagrammes)", idx, flow.datagrams.len());

        let corpus = Corpus::from_datagrams(&flow.datagrams, Some(idx));
        info!("Corpus créé: {} PDUs, {} octets", corpus.len(), corpus.total_bytes());

        let result = engine.infer(corpus, &registry);
        info!("Inférence terminée: {} couches trouvées", result.layers.len());

        results.push(serde_json::json!({
            "flow_index": idx,
            "flow": flow,
            "result": result,
        }));
    }

    let output = serde_json::json!({
        "flows": results,
        "summary": {
            "total_flows": results.len(),
        }
    });

    fs::write(&args.out, serde_json::to_string_pretty(&output)?)
        .with_context(|| format!("Échec de l'écriture du fichier: {}", args.out))?;

    info!("Résultats sauvegardés dans: {}", args.out);

    Ok(())
}


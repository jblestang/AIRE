# Protocol Infer

Application Rust pour l'inférence automatique de la structure de protocoles inconnus à partir de fichiers PCAP, basée sur le principe **PDU = PCI || SDU** (peel & recurse) et l'optimisation MDL (Minimum Description Length).

## Concept

### PDU = PCI || SDU

Le système applique une approche récursive de "peel & recurse" :
- **PDU** (Protocol Data Unit) : unité complète de données
- **PCI** (Protocol Control Information) : en-tête/information de contrôle
- **SDU** (Service Data Unit) : données utiles

À chaque niveau, le système :
1. Génère des hypothèses sur la structure (bundling, headers, TLV, etc.)
2. Parse le corpus selon chaque hypothèse
3. Score chaque hypothèse via MDL
4. Choisit la meilleure hypothèse
5. Extrait les SDUs et recommence récursivement

### MDL (Minimum Description Length)

Le score MDL combine :
- **DL(Model)** : complexité du modèle (pénalité)
- **DL(Data|Model)** : taille des données encodées selon le modèle (entropie + compression)
- **Penalties** : sur-découpage, exceptions, ambiguïté

Le système minimise `DL(Model) + DL(Data|Model) + Penalties` pour choisir la meilleure hypothèse.

## Architecture

### Workspace Cargo

```
protocol_infer/
├── core/          # Bibliothèque principale
├── cli/           # Interface en ligne de commande
└── gui/           # Interface graphique (egui)
```

### Système de Plugins

L'architecture plugin permet d'ajouter de nouveaux mécanismes sans modifier le cœur :

- **HypothesisGenerator** : génère des hypothèses candidates
- **Parser** : parse un corpus selon une hypothèse
- **Scorer** : score une hypothèse via MDL

### Mécanismes Supportés

1. **Length-Prefix Bundling** : messages préfixés par leur longueur
2. **Delimiter Bundling** : messages séparés par un délimiteur
3. **Fixed Header** : en-tête de taille fixe
4. **Extensible Bitmap** : bitmap avec bit de continuation (PER-like)
5. **TLV** : Tag-Length-Value (BER-like)
6. **Varint Key-WireType** : protobuf-like avec varint

## Installation

```bash
# Cloner le dépôt
git clone <repository>
cd AIRE

# Compiler
cargo build --release

# Tests
cargo test
```

## Usage

### CLI

Vous pouvez utiliser soit les scripts shell fournis, soit les commandes cargo directement :

**Avec les scripts (recommandé) :**
```bash
# Analyser un fichier PCAP
./run-cli.sh --pcap capture.pcap --out results.json

# Analyser un flow spécifique
./run-cli.sh --pcap capture.pcap --out results.json --flow 0

# Personnaliser la profondeur et top-K
./run-cli.sh --pcap capture.pcap --out results.json --max-depth 8 --top-k 20
```

**Avec cargo directement :**
```bash
# Analyser un fichier PCAP
cargo run -p protocol_infer_cli -- --pcap capture.pcap --out results.json

# Analyser un flow spécifique
cargo run -p protocol_infer_cli -- --pcap capture.pcap --out results.json --flow 0

# Personnaliser la profondeur et top-K
cargo run -p protocol_infer_cli -- --pcap capture.pcap --out results.json --max-depth 8 --top-k 20
```

### GUI

**Avec le script (recommandé) :**
```bash
./run-gui.sh
```

**Avec cargo directement :**
```bash
cargo run -p protocol_infer_gui
```

La GUI permet de :
- Ouvrir un fichier PCAP
- Sélectionner un flow
- Lancer l'inférence (en arrière-plan)
- Inspecter les couches inférées
- Visualiser les messages avec hexdump
- Analyser les métriques (entropie, alignment, scores MDL)

## Format de Sortie JSON

```json
{
  "flows": [
    {
      "flow_index": 0,
      "flow": { ... },
      "result": {
        "layers": [
          {
            "hypothesis": {
              "LengthPrefixBundle": {
                "offset": 0,
                "width": 2,
                "endian": "Little",
                "includes_header": false
              }
            },
            "score": {
              "breakdown": {
                "mdl_model_bits": 32.0,
                "mdl_data_bits": 1024.0,
                "parse_success_ratio": 0.98,
                "alignment_gain_bits": 0.0,
                "entropy_drop_bits": 0.0,
                "penalties_bits": 16.0
              },
              "total_bits": 1072.0
            },
            "parsed": { ... },
            "sdu_corpus": { ... }
          }
        ],
        "corpus": { ... }
      }
    }
  ]
}
```

## Limitations

### Chiffrement et Compression

Le système ne peut pas inférer la structure de protocoles :
- **Chiffrés** : les patterns sont masqués
- **Comprimés** : la régularité est perdue
- **Obfusqués** : structure intentionnellement cachée

### Complexité

L'inférence peut être coûteuse pour :
- Très gros corpus (>100MB)
- Profondeur élevée (>10 couches)
- Nombreux flows simultanés

### Exactitude

L'inférence est **best-effort** et peut :
- Manquer des structures complexes
- Produire des faux positifs
- Nécessiter une validation manuelle

## Tests

```bash
# Tous les tests
cargo test

# Tests spécifiques
cargo test test_length_prefix_bundling
cargo test test_inference_engine
```

Les tests incluent des corpus synthétiques pour chaque mécanisme supporté.

## Extension : Ajouter un Plugin

### 1. Créer un Générateur

```rust
use protocol_infer_core::plugin::HypothesisGenerator;
use protocol_infer_core::{Corpus, Hypothesis};

pub struct MyGenerator;

impl HypothesisGenerator for MyGenerator {
    fn name(&self) -> &'static str {
        "MyGenerator"
    }

    fn propose(&self, corpus: &Corpus) -> Vec<Hypothesis> {
        // Générer des hypothèses
        vec![Hypothesis::FixedHeader { len: 8 }]
    }
}
```

### 2. Créer un Parser

```rust
use protocol_infer_core::parser::{Parser, ParsedCorpus};
use protocol_infer_core::{Corpus, Hypothesis};

pub struct MyParser;

impl Parser for MyParser {
    fn name(&self) -> &'static str {
        "MyParser"
    }

    fn applicable(&self, h: &Hypothesis) -> bool {
        matches!(h, Hypothesis::FixedHeader { len: 8 })
    }

    fn parse_corpus(&self, corpus: &Corpus, h: &Hypothesis) -> ParsedCorpus {
        // Parser le corpus
        ParsedCorpus::new(vec![])
    }
}
```

### 3. Enregistrer le Plugin

```rust
let mut registry = PluginRegistry::new();
registry.register_generator(Box::new(MyGenerator));
registry.register_parser(Box::new(MyParser));
```

## Disclaimer Légal

**⚠️ AVERTISSEMENT IMPORTANT**

Cette application est conçue uniquement à des fins **légitimes** :

- Analyse de protocoles pour lesquels vous avez **autorisation explicite**
- Recherche académique et éducative
- Tests de sécurité sur vos propres systèmes
- Reverse engineering de protocoles **open-source** ou **propriétaires** pour lesquels vous avez une licence

**INTERDICTIONS STRICTES** :

- ❌ Analyser des captures réseau sans autorisation
- ❌ Intercepter du trafic réseau non autorisé
- ❌ Violer des lois sur la protection des données
- ❌ Utiliser pour des activités illégales

**L'utilisation de cet outil est de votre seule responsabilité.** Les auteurs ne peuvent être tenus responsables d'une utilisation non autorisée ou illégale.

Respectez toujours :
- Les lois locales et internationales
- Les termes de service des protocoles analysés
- Les droits de propriété intellectuelle
- Les réglementations sur la protection des données (RGPD, etc.)

## Licence

MIT OR Apache-2.0

## Contribution

Les contributions sont les bienvenues ! Veuillez :
1. Créer une issue pour discuter des changements majeurs
2. Soumettre une PR avec des tests
3. Respecter le style de code Rust standard

## Références

- **MDL** : Minimum Description Length Principle
- **PER** : Packed Encoding Rules (ASN.1)
- **BER** : Basic Encoding Rules (ASN.1)
- **Protobuf** : Protocol Buffers (Google)


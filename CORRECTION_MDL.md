# Correction du calcul MDL

## Problème identifié

Le calcul original du MDL Data était incorrect :
- **Seuls les SDUs étaient comptés** dans `mdl_data_bits`
- **Les PCI (headers) n'étaient pas inclus**
- **Pas de comparaison avec les données brutes**

Cela pénalisait les modèles qui extraient beaucoup de SDUs, même s'ils étaient bien structurés.

## Corrections apportées

### 1. Inclusion de PCI + Fields + SDU dans MDL Data

**Avant** :
```rust
// Seulement les SDUs
let mdl_data_bits = entropy(&sdu_data) * total_sdu_bytes as f64;
```

**Après** :
```rust
// PCI + Fields + SDU (toutes les données selon le modèle)
let mut model_data = Vec::new();
model_data.extend_from_slice(&pci_data);
model_data.extend_from_slice(&field_data);
model_data.extend_from_slice(&sdu_data);
let mdl_data_bits = entropy(&model_data) * model_data.len() as f64;
```

### 2. Calcul du gain d'entropie

Ajout du calcul de `entropy_drop_bits` qui compare l'entropie des données brutes avec l'entropie des données selon le modèle :

```rust
let entropy_drop_bits = {
    let raw_entropy_bits = entropy(&raw_data) * raw_data.len() as f64;
    let model_entropy_bits = entropy(&model_data) * model_data.len() as f64;
    (raw_entropy_bits - model_entropy_bits).max(0.0)
};
```

Ce gain est soustrait du score total dans `ScoreBreakdown::total_bits()`.

### 3. Utilisation de la compression comme proxy

Le MDL Data utilise maintenant le minimum entre :
- Entropie empirique : `entropy * bytes * 8`
- Compression (Deflate) : `compressed_size * 8`

La compression capture mieux les patterns répétitifs que l'entropie seule.

## Résultats

### Avant la correction
- TLV Tag=1, Length=2 : score = 13,080 ou 23,192 bits
- Meilleur modèle : Tag=3, Length=1 byte, score = 6,000 bits

### Après la correction
- TLV Tag=1, Length=2 : score = 14,024 ou 24,168 bits
- Meilleur modèle : Tag=2, Length=2 bytes (DefiniteMedium), score = 2,632 bits

## Problème restant

Tag=1, Length=2 a encore un score élevé à cause de :
1. **100 exceptions** (sans length_includes_header) ou **12 exceptions** (avec)
2. **MDL Data élevé** : 11,888 ou 23,424 bits
3. **Pénalités** : 2,112 ou 720 bits

Les exceptions indiquent que le parser TLV échoue souvent pour cette hypothèse, probablement parce que :
- Le length lu est incorrect
- Le parser ne gère pas correctement tous les cas edge
- La structure réelle du protocole peut être différente

## Prochaines étapes

1. **Analyser les exceptions** : comprendre pourquoi le parser échoue pour Tag=1, Length=2
2. **Vérifier le parser TLV** : s'assurer qu'il gère correctement tous les cas
3. **Tester avec d'autres PCAPs** : valider que la correction fonctionne pour d'autres protocoles


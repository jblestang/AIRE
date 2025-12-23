# Vérification du Calcul MDL

## Corrections Apportées

### 1. ✅ MDL Data - Suppression de la Normalisation Incorrecte

**Avant** :
```rust
let cost_per_byte = sdu_bits / sdu_data.len();
let normalized_mdl_data = cost_per_byte * corpus.total_bytes(); // ❌ INCORRECT
```

**Problème** : On multipliait par `corpus.total_bytes()` au lieu de `sdu_data.len()`, ce qui pénalisait les hypothèses qui extraient beaucoup de SDUs.

**Après** :
```rust
let mdl_data_bits = min(entropy * len, compressed); // ✅ CORRECT
```

**Résultat** :
- Avant : `mdl_data = 23907.36` (normalisé incorrectement)
- Après : `mdl_data = 22448.00` (sans normalisation)

### 2. ✅ MDL Model - Inclusion de PCI et Fields

**Actuellement** :
```rust
let mdl_model_bits = base_model_bits + pci_bits + field_bits;
```

**Justification** : Les PCI et Fields sont des métadonnées du modèle, pas des données. Ils font partie du coût du modèle.

**Résultat** :
- `mdl_model = 1032.00` (inclut PCI + Fields)

### 3. ⚠️ Entropy Drop - Problème Restant

**Actuellement** :
```rust
let raw_ratio = raw_compressed / raw_data.len();
let sdu_ratio = sdu_compressed / sdu_data.len();
if sdu_ratio < raw_ratio {
    entropy_drop = (raw_ratio - sdu_ratio) * sdu_data.len();
}
```

**Problème** :
- `raw_data` = 6910 bytes (PCI + Fields + SDU)
- `sdu_data` = 6522 bytes (seulement SDU)
- `raw_ratio = 3.322 bits/byte`
- `sdu_ratio = 3.442 bits/byte`
- `sdu_ratio > raw_ratio` → `entropy_drop = 0`

**Pourquoi c'est un problème** :
- On compare des pommes avec des oranges
- Les SDUs sont un sous-ensemble des données brutes
- Les SDUs peuvent être plus compressibles que leur partie correspondante dans les données brutes, mais moins compressibles que toutes les données brutes (qui incluent PCI + Fields)

**Solution Possible** :
1. Comparer les SDUs avec leur partie correspondante dans les données brutes (mais comment identifier cette partie ?)
2. Comparer `raw_compressed` vs `model_compressed` (mais `model_compressed = 23424 > raw_compressed = 23072`)
3. Ne pas utiliser `entropy_drop` si les SDUs ne sont pas plus compressibles que toutes les données brutes

## État Actuel

Pour **Tag=1, Len=2 avec `length_includes_header=true`** :
- `mdl_model = 1032.00` ✅
- `mdl_data = 22448.00` ✅ (corrigé)
- `entropy_drop = 0.00` ⚠️ (problème restant)
- `penalties = 592.00` ✅ (padding Ethernet non pénalisé)
- `total = 24072.00`

## Comparaison avec Meilleure Hypothèse

**Meilleure hypothèse actuelle** : `Tlv { tag_bytes: 3, len_offset: 3, len_rule: DefiniteShort, length_includes_header: true }`
- Score : `7128.00`
- `mdl_model = 1152.00`
- `mdl_data = 3960.00`
- `penalties = 2016.00`

**Tag=1, Len=2** :
- Score : `24072.00` (beaucoup plus élevé)
- `mdl_data = 22448.00` (beaucoup plus élevé car plus de SDUs : 6522 bytes vs ?)

## Conclusion

Le calcul MDL Data est maintenant **correct** (sans normalisation incorrecte). Le problème principal est que :
1. Le MDL Data est élevé car il y a beaucoup de SDUs (6522 bytes)
2. L'entropy_drop est 0 car les SDUs ne sont pas plus compressibles que toutes les données brutes
3. Le score total reste élevé (24072) comparé à la meilleure hypothèse (7128)

**Question** : Est-ce que le MDL Data devrait être normalisé par le nombre de SDUs ou par le nombre de bytes de SDUs pour comparer équitablement les hypothèses ?


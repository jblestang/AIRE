# Analyse : Pourquoi TLV Tag=1, Length=2 bytes n'est pas sélectionné

## Résultats observés

### Hypothèse : TLV Tag=1, Length=2 bytes (tag à offset 0, length à offset 1)

**Sans `length_includes_header` (false)** :
- Score total : **13,080 bits**
- MDL Data : 10,944 bits
- Pénalités : 2,112 bits (100 exceptions × 16 + petits segments)
- SDU_count : 28
- SDU_bytes : 3,118
- Exceptions : 100

**Avec `length_includes_header` (true)** :
- Score total : **23,192 bits**
- MDL Data : 22,448 bits
- Pénalités : 720 bits (12 exceptions × 16 + petits segments)
- SDU_count : 120
- SDU_bytes : 6,522
- Exceptions : 12

**Meilleure hypothèse sélectionnée** :
- TLV { tag_offset: 0, tag_bytes: 3, len_offset: 3, len_rule: DefiniteShort, length_includes_header: true }
- Score : **6,000 bits**

## Problèmes identifiés

### 1. Score trop élevé pour TLV Tag=1, Length=2

Même avec `length_includes_header=true`, le score (23,192) est **3.8× pire** que le meilleur (6,000).

**Causes** :
- **MDL Data trop élevé** (22,448 bits) : Avec 120 SDUs extraits, l'entropie/compression est élevée
- Les SDUs extraits ne sont probablement pas bien structurés (peu compressibles)
- Le scoring MDL pénalise les hypothèses qui extraient beaucoup de données peu régulières

### 2. Exceptions encore présentes

Même avec `length_includes_header=true`, il reste **12 exceptions**, ce qui ajoute 192 bits de pénalité.

### 3. Comparaison avec le meilleur modèle

Le meilleur modèle (Tag=3, Length=1 byte) :
- Extrait moins de SDUs mais mieux structurés
- Moins d'exceptions
- Score MDL Data beaucoup plus faible (3,960 vs 22,448)

## Conclusion

Le problème principal est que **TLV Tag=1, Length=2 bytes extrait trop de SDUs mal structurés**, ce qui donne un score MDL Data très élevé. Le scoring MDL favorise les modèles qui extraient des données **régulières et compressibles**, pas nécessairement le plus grand nombre de SDUs.

## Recommandations

1. **Vérifier les données réelles** : Analyser si les SDUs extraits par TLV Tag=1, Length=2 sont vraiment bien structurés
2. **Ajuster le scoring** : Peut-être que le scoring MDL pénalise trop les hypothèses avec beaucoup de SDUs
3. **Améliorer le parser** : Vérifier si le parser gère correctement tous les cas edge pour `length_includes_header=true` avec `DefiniteMedium`


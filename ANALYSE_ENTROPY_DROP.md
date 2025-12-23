# Analyse de entropy_drop pour Tag=1, Len=2

## Problème

Pour l'hypothèse **Tag=1, Len=2 avec `length_includes_header=true`**, `entropy_drop = 0.00`.

## Données Actuelles

```
raw_data = 6882 bytes (toutes les données brutes)
raw_compressed = 22968 bits
raw_ratio = 3.337 bits/byte

sdu_data = 6522 bytes (seulement les SDUs extraits)
sdu_compressed = 22448 bits
sdu_ratio = 3.442 bits/byte

model_data = PCI (0) + Fields (360) + SDU (6522) = 6882 bytes
model_compressed = 23384 bits
model_ratio = 3.399 bits/byte
```

## Problème Identifié

### Problème Principal
- `sdu_ratio (3.442) > raw_ratio (3.337)`
- Donc `entropy_drop = 0` quand on compare les SDUs avec les données brutes
- **Cause** : Les SDUs (6522 bytes) sont moins compressibles que toutes les données brutes (6882 bytes)

### Pourquoi sdu_ratio > raw_ratio ?

1. **Les données brutes incluent Fields (360 bytes)**
   - Les Fields peuvent être plus compressibles (répétitifs, patterns)
   - Donc `raw_ratio` est meilleur que `sdu_ratio`

2. **Les SDUs sont identiques aux bytes correspondants dans les données brutes**
   - `raw_sdu_equivalent` (extrait depuis raw_data) = `sdu_data` (extrait par le parser)
   - Mêmes bytes, même ordre → même compressibilité
   - Donc `raw_sdu_compressed = sdu_compressed`

3. **La concaténation ne change pas la compressibilité**
   - Si les bytes sont identiques, la concaténation ne change pas la compressibilité
   - Donc pas de gain d'entropie

## Conclusion

`entropy_drop = 0` car :
- Les SDUs extraits sont identiques aux bytes correspondants dans les données brutes
- Ils ont la même compressibilité
- La concaténation ne change pas la compressibilité si les bytes sont identiques

**Question** : Est-ce que `entropy_drop` devrait mesurer autre chose ?
- La réduction d'entropie obtenue en structurant les données ?
- La différence entre données brutes et données structurées ?
- Ou simplement la compressibilité des SDUs extraits ?

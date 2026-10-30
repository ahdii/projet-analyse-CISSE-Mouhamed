# Projet 1 — Analyse des journaux d'un pare-feu

**Auteur** : Mouhamed CISSE

## Lancer le projet
```bash
pip install -r requirements.txt
python analyse.py
```
Le script lit `data/logs_reseau.csv`, nettoie les données, écrit `resultats.json`
et enregistre les graphiques dans `figures/`.

## Contenu
- `analyse.py` : nettoyage, calculs, figures
- `resultats.json` : les 5 résultats (généré)
- `rapport.md` : interprétation et recommandations
- `figures/` : graphiques PNG

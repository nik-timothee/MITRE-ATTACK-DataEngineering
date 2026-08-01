# MITRE ATT&CK Data Engineering & Interactive Dashboard

## Projet étudiant — Cycle Ingénieur Cybersécurité — Groupe 9

> Analyse et visualisation du framework MITRE ATT&CK Enterprise à partir des données STIX 2.0.

---

## 1. Présentation du projet

MITRE ATT&CK est un référentiel mondial décrivant les tactiques, techniques et procédures (TTP) utilisées par les groupes d'attaquants.

Ce projet consiste à transformer les données brutes du framework MITRE ATT&CK, fournies au format JSON STIX 2.0, en données structurées et exploitables pour l'analyse.

Le projet met en œuvre une chaîne de traitement Data Engineering permettant de :

- télécharger les données MITRE ATT&CK
- explorer et comprendre la structure STIX 2.0
- parser et normaliser les objets STIX
- construire des tables structurées
- organiser les données selon un schéma en étoile
- produire des fichiers analytiques au format Parquet
- stocker les données dans AWS S3
- effectuer des analyses statistiques
- construire une matrice tactiques/techniques
- créer un dashboard interactif avec Power BI

---

## 2. Problématique

> Comment transformer les données brutes du framework MITRE ATT&CK en un modèle de données structuré permettant d'analyser les groupes APT, les tactiques, les techniques et les plateformes ciblées, puis de visualiser ces informations dans un dashboard interactif ?

---

## 3. Technologies utilisées

| Technologie | Utilisation |
|---|---|
| R | Traitement et transformation des données |
| jsonlite | Lecture du JSON STIX 2.0 |
| dplyr | Manipulation et transformation des données |
| readr | Lecture et écriture des fichiers CSV |
| tidyr | Manipulation des données imbriquées |
| arrow | Export et manipulation des fichiers Parquet |
| aws.s3 | Upload vers AWS S3 |
| AWS S3 | Stockage cloud des données |
| Power BI Desktop | Analyse et visualisation |
| Git / GitHub | Versionnement et collaboration |
| STIX 2.0 | Format des données MITRE ATT&CK |

---

## 4. Architecture du projet

```
                    MITRE ATT&CK
                         │
                         ▼
              JSON STIX 2.0
                         │
                         ▼
              ┌──────────────────┐
              │      R / RStudio │
              │   jsonlite/dplyr │
              └────────┬─────────┘
                       │
                       ▼
                Parsing STIX
                       │
                       ▼
              Données normalisées
                       │
             ┌─────────┴─────────┐
             │                   │
             ▼                   ▼
       CSV structurés       Schéma en étoile
             │                   │
             └─────────┬─────────┘
                       │
                       ▼
                  Parquet
                       │
                       ▼
                   AWS S3
                       │
                       ▼
                 Power BI
                       │
                       ▼
             Dashboard interactif
```

---

## 5. Organisation du dépôt

```
MITRE-ATTACK-DataEngineering/
│
├── data/
│   ├── raw/
│   │   └── enterprise-attack.json
│   │
│   ├── processed/
│   │   ├── tactics.csv
│   │   ├── techniques.csv
│   │   ├── groups.csv
│   │   ├── malware.csv
│   │   ├── relationships.csv
│   │   └── technique_tactic.csv
│   │
│   ├── warehouse/
│   │   ├── dim_tactics.csv
│   │   ├── dim_techniques.csv
│   │   ├── dim_groups.csv
│   │   ├── dim_platforms.csv
│   │   ├── fact_technique_utilisee_par_groupe.csv
│   │   └── bridge_technique_platform.csv
│   │
│   ├── analytics/
│   │   ├── top_groups.csv
│   │   ├── top_techniques.csv
│   │   ├── top_tactics.csv
│   │   ├── top_platforms.csv
│   │   ├── techniques_actives.csv
│   │   ├── techniques_emergentes.csv
│   │   └── apt_analysis.csv
│   │
│   └── parquet/
│       ├── dim_tactics.parquet
│       ├── dim_techniques.parquet
│       ├── dim_groups.parquet
│       ├── dim_platforms.parquet
│       ├── fact_technique_utilisee_par_groupe.parquet
│       └── bridge_technique_platform.parquet
│
├── scripts/
│   ├── 01_download_data.R
│   ├── 02_explore_data.R
│   ├── 03_parse_stix.R
│   ├── 04_star_schema.R
│   ├── 05_export_parquet.R
│   ├── 06_upload_s3.R
│   └── 07_transformations.R
│
├── powerbi/
│   └── MITRE_ATTACK_G9_Dashboard.pbix
│
├── docs/
│
├── README.md
└── .gitignore
```

---

## 6. Pipeline de traitement

Les scripts doivent être exécutés dans l'ordre suivant :

```
01_download_data.R      → Téléchargement du JSON MITRE ATT&CK
        ↓
02_explore_data.R       → Exploration de la structure STIX 2.0
        ↓
03_parse_stix.R         → Extraction des entités STIX
        ↓
04_star_schema.R        → Construction du schéma en étoile
        ↓
05_export_parquet.R     → Export au format Parquet
        ↓
06_upload_s3.R          → Upload vers AWS S3
        ↓
07_transformations.R    → Analyses et préparation Power BI
```

---

## 7. Schéma en étoile

```
             DIM_TACTICS
                  │
                  │
                  ▼
DIM_GROUPS ─── FACT_TECHNIQUE_UTILISEE_PAR_GROUPE ─── DIM_TECHNIQUES
                  │
                  │
                  ▼
             DIM_PLATFORMS
```

---

## 8. Installation

### Prérequis

- R (>= 4.1)
- RStudio
- Git
- Power BI Desktop (Windows uniquement)
- Compte AWS (pour S3)

### Cloner le dépôt

```bash
git clone https://github.com/nik-timothee/MITRE-ATTACK-DataEngineering
cd MITRE-ATTACK-DataEngineering
```

### Installer les packages R

```r
install.packages(c(
  "jsonlite",
  "dplyr",
  "readr",
  "tidyr",
  "arrow",
  "aws.s3",
  "stringr",
  "usethis"
))
```

### Configurer les credentials AWS

Les credentials AWS ne doivent jamais être écrits dans les scripts.
Configurez-les dans votre fichier `.Renviron` :

```bash
# Dans la console RStudio
usethis::edit_r_environ()
```

Ajoutez vos informations :

```
AWS_ACCESS_KEY_ID=votre_access_key
AWS_SECRET_ACCESS_KEY=votre_secret_key
AWS_DEFAULT_REGION=eu-north-1
AWS_BUCKET_NAME=votre-bucket-s3
```

Redémarrez RStudio puis vérifiez :

```r
Sys.getenv("AWS_BUCKET_NAME")
```

---

## 9. Dashboard Power BI

Le fichier se trouve dans :

```
powerbi/MITRE_ATTACK_G9_Dashboard.pbix
```

### KPI affichés

| KPI | Description |
|---|---|
| Techniques | Nombre total de techniques ATT&CK |
| Tactiques | Nombre total de tactiques |
| Groupes APT | Nombre de groupes d'attaquants |
| Plateformes | Nombre de plateformes ciblées |

### Visualisations

1. **Top 10 Techniques** — techniques les plus utilisées par les groupes APT
2. **Top 10 Groupes APT** — groupes selon le nombre de techniques associées
3. **Tactiques les plus utilisées** — fréquence d'utilisation des tactiques
4. **Répartition par plateforme** — plateformes ciblées (Windows, Linux, macOS…)
5. **Matrice ATT&CK** — matrice interactive Tactiques × Techniques
6. **Techniques émergentes** — 50 techniques les plus récentes
7. **Analyse APT** — analyse détaillée de APT28, Lazarus Group et APT41

### Filtres interactifs

- Tactique
- Plateforme
- Groupe APT
- Technique

---

## 10. AWS S3

Les données Parquet sont stockées dans un bucket AWS S3 privé organisé comme suit :

```
votre-bucket-s3/
├── raw/
└── processed/
    └── parquet/
        ├── dim_tactics.parquet
        ├── dim_techniques.parquet
        ├── dim_groups.parquet
        ├── dim_platforms.parquet
        ├── fact_technique_utilisee_par_groupe.parquet
        └── bridge_technique_platform.parquet
```

> ⚠️ Les credentials AWS ne sont jamais stockés dans ce dépôt.

---

## 11. Sécurité

Les éléments suivants ne doivent jamais être versionnés sur GitHub :

- Clés AWS (Access Key / Secret Key)
- Fichier `.Renviron`
- Tokens ou mots de passe
- Données brutes volumineuses

Le fichier `.gitignore` contient notamment :

```
.Renviron
.Rhistory
.RData
.Rproj.user/
data/raw/
*.pem
*.key
```

---

## 12. Source des données

Les données proviennent du dépôt officiel MITRE CTI :

```
https://github.com/mitre/cti
```

> Les résultats (nombre de techniques, groupes, relations) dépendent de la version du référentiel
> MITRE ATT&CK téléchargée au moment de l'exécution du pipeline.

---

## 13. Auteurs

Projet réalisé dans le cadre du **Cycle Ingénieur Cybersécurité — Master 1 Sécurité Informatique**

**Groupe 9 — MITRE ATT&CK Data Engineering**

| Membre |
|---|
| Timothée |
| Baba |
| Bado |

Année académique : **2025–2026**

---

## 14. Licence des données

MITRE ATT&CK est un projet développé par MITRE.
Les données sont issues du dépôt public :

```
https://github.com/mitre/cti
```

Consulter les conditions d'utilisation associées aux données MITRE ATT&CK avant toute redistribution.
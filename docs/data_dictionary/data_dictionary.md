# Dictionnaire des données — MITRE ATT&CK Data Engineering

**Projet** : Groupe 9 — Cycle Ingénieur Cybersécurité  
**Année** : 2025–2026  
**Source des données** : MITRE ATT&CK Enterprise — JSON STIX 2.0  
**Dépôt** : https://github.com/nik-timothee/MITRE-ATTACK-DataEngineering

---

## Table des matières

1. [Tables brutes extraites](#1-tables-brutes-extraites)
   - [tactics](#11-tactics)
   - [techniques](#12-techniques)
   - [groups](#13-groups)
   - [malware](#14-malware)
   - [relationships](#15-relationships)
   - [technique_tactic](#16-technique_tactic)
2. [Tables du schéma en étoile](#2-tables-du-schéma-en-étoile)
   - [dim_tactics](#21-dim_tactics)
   - [dim_techniques](#22-dim_techniques)
   - [dim_groups](#23-dim_groups)
   - [dim_platforms](#24-dim_platforms)
   - [fact_technique_utilisee_par_groupe](#25-fact_technique_utilisee_par_groupe)
   - [bridge_technique_platform](#26-bridge_technique_platform)
3. [Tables analytiques](#3-tables-analytiques)
   - [top_groups](#31-top_groups)
   - [top_techniques](#32-top_techniques)
   - [top_tactics](#33-top_tactics)
   - [top_platforms](#34-top_platforms)
   - [techniques_actives](#35-techniques_actives)
   - [techniques_emergentes](#36-techniques_emergentes)
   - [apt_analysis](#37-apt_analysis)
4. [Modèle de données — Schéma en étoile](#4-modèle-de-données--schéma-en-étoile)
5. [Relations entre les entités](#5-relations-entre-les-entités)
6. [Utilisation dans Power BI](#6-utilisation-dans-power-bi)
7. [Flux global des données](#7-flux-global-des-données)
8. [Résumé des tables](#8-résumé-des-tables)

---

## 1. Tables brutes extraites

> Fichiers produits par `03_parse_stix.R`  
> Emplacement : `data/processed/`

---

### 1.1 tactics

**Fichier** : `data/processed/tactics.csv`  
**Description** : Contient les 14 tactiques du framework Enterprise ATT&CK. Une tactique représente une étape ou un objectif dans la chaîne d'attaque (ex. Initial Access, Execution, Persistence).  
**Source STIX** : Objets de type `x-mitre-tactic`  
**Script** : `03_parse_stix.R`

| Colonne | Type | Description | Source STIX | Rôle |
|---|---|---|---|---|
| `id` | character | Identifiant unique STIX au format UUID | `id` | Clé primaire |
| `name` | character | Nom complet de la tactique (ex. `Initial Access`, `Execution`) | `name` | Attribut |
| `short_name` | character | Nom court utilisé dans `kill_chain_phases` des techniques (ex. `initial-access`) | `x_mitre_shortname` | Clé de jointure |
| `description` | character | Description textuelle de la tactique. Peut être `NA` si absente. | `description` | Attribut |

---

### 1.2 techniques

**Fichier** : `data/processed/techniques.csv`  
**Description** : Contient l'ensemble des techniques et sous-techniques du framework Enterprise ATT&CK (858 au total). Les sous-techniques sont des variantes plus précises d'une technique principale.  
**Source STIX** : Objets de type `attack-pattern`  
**Script** : `03_parse_stix.R`

| Colonne | Type | Description | Source STIX | Rôle |
|---|---|---|---|---|
| `id` | character | Identifiant unique STIX au format UUID | `id` | Clé primaire |
| `attack_id` | character | Identifiant MITRE lisible (ex. `T1059` ou `T1059.001` pour une sous-technique) | `external_references[mitre-attack].external_id` | Identifiant métier |
| `name` | character | Nom de la technique (ex. `Command and Scripting Interpreter`) | `name` | Attribut |
| `description` | character | Description complète. Peut être `NA`. | `description` | Attribut |
| `platforms` | character | Plateformes ciblées séparées par virgule (ex. `Windows, Linux, macOS`) | `x_mitre_platforms` | Attribut |
| `revoked` | logical | `TRUE` si la technique a été remplacée par une autre | `revoked` | Statut |
| `deprecated` | logical | `TRUE` si la technique a été retirée sans remplacement | `x_mitre_deprecated` | Statut |
| `created` | character | Date de création dans le référentiel STIX (format ISO 8601) | `created` | Attribut temporel |

---

### 1.3 groups

**Fichier** : `data/processed/groups.csv`  
**Description** : Contient les groupes d'attaquants (APT) référencés dans MITRE ATT&CK. Chaque groupe est un acteur malveillant organisé, souvent associé à un État.  
**Source STIX** : Objets de type `intrusion-set`  
**Script** : `03_parse_stix.R`

| Colonne | Type | Description | Source STIX | Rôle |
|---|---|---|---|---|
| `id` | character | Identifiant unique STIX au format UUID | `id` | Clé primaire |
| `name` | character | Nom principal du groupe (ex. `APT28`, `Lazarus Group`, `APT41`) | `name` | Attribut |
| `aliases` | character | Noms alternatifs séparés par virgule (ex. `Fancy Bear, Sofacy`). `NA` si aucun alias. | `aliases` | Attribut |

---

### 1.4 malware

**Fichier** : `data/processed/malware.csv`  
**Description** : Contient les logiciels malveillants référencés dans MITRE ATT&CK, utilisés par les groupes APT pour mettre en œuvre des techniques d'attaque.  
**Source STIX** : Objets de type `malware`  
**Script** : `03_parse_stix.R`

| Colonne | Type | Description | Source STIX | Rôle |
|---|---|---|---|---|
| `id` | character | Identifiant unique STIX au format UUID | `id` | Clé primaire |
| `name` | character | Nom du logiciel malveillant (ex. `WannaCry`, `Mimikatz`). `NA` si absent. | `name` | Attribut |

---

### 1.5 relationships

**Fichier** : `data/processed/relationships.csv`  
**Description** : Contient toutes les relations STIX entre les objets du framework. C'est la table centrale qui relie les groupes APT aux techniques qu'ils utilisent.  
**Source STIX** : Objets de type `relationship`  
**Script** : `03_parse_stix.R`

| Colonne | Type | Description | Source STIX | Rôle |
|---|---|---|---|---|
| `source` | character | Identifiant STIX de l'objet source (groupe APT, malware…) | `source_ref` | Clé étrangère source |
| `target` | character | Identifiant STIX de l'objet cible (technique…) | `target_ref` | Clé étrangère cible |
| `relation` | character | Type de relation (`uses`, `mitigates`, `subtechnique-of`…) | `relationship_type` | Attribut |

**Types de relations principaux** :

| Valeur | Signification |
|---|---|
| `uses` | Un groupe ou logiciel utilise une technique |
| `mitigates` | Une mitigation couvre une technique |
| `subtechnique-of` | Lien entre une sous-technique et sa technique parente |

---

### 1.6 technique_tactic

**Fichier** : `data/processed/technique_tactic.csv`  
**Description** : Table de correspondance entre les techniques et les tactiques. Une technique peut appartenir à plusieurs tactiques (1 090 lignes au total).  
**Source STIX** : Champ `kill_chain_phases` des objets `attack-pattern`  
**Script** : `03_parse_stix.R`

| Colonne | Type | Description | Source STIX | Rôle |
|---|---|---|---|---|
| `technique_id` | character | Identifiant STIX de la technique (UUID) | `id` | Clé étrangère |
| `attack_id` | character | Identifiant MITRE de la technique (ex. `T1059`) | `external_references` | Identifiant métier |
| `tactic` | character | Nom court de la tactique (ex. `execution`, `persistence`) — correspond au `short_name` de `tactics` | `kill_chain_phases.phase_name` | Clé de jointure |

---

## 2. Tables du schéma en étoile

> Fichiers produits par `04_star_schema.R`  
> Emplacement : `data/warehouse/`

---

### 2.1 dim_tactics

**Fichier** : `data/warehouse/dim_tactics.csv`  
**Description** : Dimension des tactiques. Version normalisée de la table `tactics`.  
**Rôle** : Dimension

| Colonne | Type | Description | Rôle |
|---|---|---|---|
| `id` | character | Identifiant STIX unique | Clé primaire |
| `name` | character | Nom complet de la tactique | Attribut |
| `short_name` | character | Nom court pour les jointures avec `technique_tactic` | Clé de jointure |
| `description` | character | Description de la tactique | Attribut |

---

### 2.2 dim_techniques

**Fichier** : `data/warehouse/dim_techniques.csv`  
**Description** : Dimension des techniques. Version enrichie avec la date de création (858 techniques).  
**Rôle** : Dimension

| Colonne | Type | Description | Rôle |
|---|---|---|---|
| `id` | character | Identifiant STIX unique | Clé primaire |
| `attack_id` | character | Identifiant MITRE (ex. `T1059`) | Identifiant métier |
| `name` | character | Nom de la technique | Attribut |
| `description` | character | Description complète | Attribut |
| `platforms` | character | Plateformes ciblées (séparées par virgule) | Attribut |
| `revoked` | logical | Technique révoquée | Statut |
| `deprecated` | logical | Technique dépréciée | Statut |
| `created` | character | Date de création (ISO 8601) | Attribut temporel |

---

### 2.3 dim_groups

**Fichier** : `data/warehouse/dim_groups.csv`  
**Description** : Dimension des groupes APT.  
**Rôle** : Dimension

| Colonne | Type | Description | Rôle |
|---|---|---|---|
| `id` | character | Identifiant STIX unique | Clé primaire |
| `name` | character | Nom principal du groupe APT | Attribut |
| `aliases` | character | Noms alternatifs du groupe | Attribut |

---

### 2.4 dim_platforms

**Fichier** : `data/warehouse/dim_platforms.csv`  
**Description** : Dimension des plateformes ciblées. Chaque ligne est une plateforme unique extraite des techniques.  
**Rôle** : Dimension

| Colonne | Type | Description | Rôle |
|---|---|---|---|
| `platform` | character | Nom de la plateforme (`Windows`, `Linux`, `macOS`, `Cloud`, `Android`, `Network Devices`…) | Clé primaire / Attribut |

---

### 2.5 fact_technique_utilisee_par_groupe

**Fichier** : `data/warehouse/fact_technique_utilisee_par_groupe.csv`  
**Description** : Table de faits centrale. Chaque ligne représente l'utilisation d'une technique par un groupe APT, issue des relations STIX de type `uses`.  
**Rôle** : Fait

| Colonne | Type | Description | Rôle |
|---|---|---|---|
| `group_id` | character | Identifiant STIX du groupe APT | Clé étrangère → `dim_groups` |
| `technique_id` | character | Identifiant STIX de la technique | Clé étrangère → `dim_techniques` |

---

### 2.6 bridge_technique_platform

**Fichier** : `data/warehouse/bridge_technique_platform.csv`  
**Description** : Table pont gérant la relation many-to-many entre techniques et plateformes.  
**Rôle** : Table pont

| Colonne | Type | Description | Rôle |
|---|---|---|---|
| `technique_id` | character | Identifiant STIX de la technique | Clé étrangère → `dim_techniques` |
| `platform` | character | Nom de la plateforme ciblée | Clé étrangère → `dim_platforms` |

---

## 3. Tables analytiques

> Fichiers produits par `07_transformations.R`  
> Emplacement : `data/analytics/`  
> Utilisées directement par Power BI Desktop

---

### 3.1 top_groups

**Fichier** : `data/analytics/top_groups.csv`  
**Description** : Classement des groupes APT selon le nombre de techniques documentées. Utilisée pour le visuel "Top 10 Groupes APT" dans Power BI.

| Colonne | Type | Description | Rôle |
|---|---|---|---|
| `group_id` | character | Identifiant STIX du groupe | Clé |
| `nb_techniques` | integer | Nombre de techniques distinctes utilisées par le groupe | Mesure |
| `name` | character | Nom du groupe APT | Dimension |
| `aliases` | character | Noms alternatifs du groupe | Attribut |

---

### 3.2 top_techniques

**Fichier** : `data/analytics/top_techniques.csv`  
**Description** : Classement des techniques selon le nombre de groupes APT qui les utilisent. Utilisée pour le visuel "Top 10 Techniques" dans Power BI.

| Colonne | Type | Description | Rôle |
|---|---|---|---|
| `technique_id` | character | Identifiant STIX de la technique | Clé |
| `nb_groupes` | integer | Nombre de groupes APT distincts utilisant cette technique | Mesure |
| `attack_id` | character | Identifiant MITRE (ex. `T1059`) | Dimension |
| `name` | character | Nom de la technique | Dimension |
| `platforms` | character | Plateformes ciblées | Attribut |
| `revoked` | logical | Technique révoquée | Statut |
| `deprecated` | logical | Technique dépréciée | Statut |
| `created` | character | Date de création | Attribut temporel |

---

### 3.3 top_tactics

**Fichier** : `data/analytics/top_tactics.csv`  
**Description** : Classement des tactiques selon leur fréquence d'utilisation. Utilisée pour le visuel "Tactiques les plus utilisées" dans Power BI.

| Colonne | Type | Description | Rôle |
|---|---|---|---|
| `tactic` | character | Nom court de la tactique (ex. `execution`, `persistence`) | Dimension |
| `nb_utilisations` | integer | Nombre total d'utilisations de cette tactique | Mesure |
| `nb_groupes` | integer | Nombre de groupes APT distincts ayant utilisé cette tactique | Mesure |

---

### 3.4 top_platforms

**Fichier** : `data/analytics/top_platforms.csv`  
**Description** : Classement des plateformes selon le nombre de techniques qui les ciblent. Utilisée pour le visuel "Répartition par plateforme" dans Power BI.

| Colonne | Type | Description | Rôle |
|---|---|---|---|
| `platform` | character | Nom de la plateforme (ex. `Windows`, `Linux`, `macOS`) | Dimension |
| `nb_techniques` | integer | Nombre de techniques distinctes ciblant cette plateforme | Mesure |

---

### 3.5 techniques_actives

**Fichier** : `data/analytics/techniques_actives.csv`  
**Description** : Sous-ensemble de `dim_techniques` contenant uniquement les 697 techniques actives (non révoquées et non dépréciées).

| Colonne | Type | Description | Rôle |
|---|---|---|---|
| `id` | character | Identifiant STIX | Clé |
| `attack_id` | character | Identifiant MITRE | Attribut |
| `name` | character | Nom de la technique | Attribut |
| `description` | character | Description | Attribut |
| `platforms` | character | Plateformes ciblées | Attribut |
| `revoked` | logical | Toujours `FALSE` dans cette table | Statut |
| `deprecated` | logical | Toujours `FALSE` dans cette table | Statut |
| `created` | character | Date de création | Attribut temporel |

---

### 3.6 techniques_emergentes

**Fichier** : `data/analytics/techniques_emergentes.csv`  
**Description** : Les 50 techniques les plus récemment ajoutées au framework, parmi les techniques actives. Utilisée pour le visuel "Techniques émergentes" dans Power BI.

| Colonne | Type | Description | Rôle |
|---|---|---|---|
| `attack_id` | character | Identifiant MITRE de la technique | Attribut |
| `name` | character | Nom de la technique | Attribut |
| `platforms` | character | Plateformes ciblées | Attribut |
| `created` | Date | Date de création (format Date R) | Attribut temporel |

---

### 3.7 apt_analysis

**Fichier** : `data/analytics/apt_analysis.csv`  
**Description** : Analyse détaillée des techniques utilisées par APT28, Lazarus Group et APT41. Utilisée pour la page "Analyse APT" dans Power BI.

| Colonne | Type | Description | Rôle |
|---|---|---|---|
| `group_name` | character | Nom du groupe APT | Dimension / Filtre |
| `technique_id` | character | Identifiant STIX de la technique | Clé |
| `attack_id` | character | Identifiant MITRE de la technique | Attribut |
| `technique` | character | Nom de la technique utilisée | Attribut |
| `tactic` | character | Tactique associée à la technique | Attribut |
| `platforms` | character | Plateformes ciblées | Attribut |

---

## 4. Modèle de données — Schéma en étoile

### 4.1 Principe

Le projet utilise une modélisation de type **Star Schema** afin de faciliter les analyses et les visualisations dans Power BI. Le modèle sépare les informations descriptives (dimensions) des informations de mesure (faits).

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

### 4.2 Table de faits : fact_technique_utilisee_par_groupe

La table de faits représente les associations entre groupes APT et techniques, issues des relations STIX de type `uses`.

| Attribut | Description | Rôle |
|---|---|---|
| `group_id` | Identifiant du groupe source | Clé étrangère → `dim_groups` |
| `technique_id` | Identifiant de la technique cible | Clé étrangère → `dim_techniques` |

### 4.3 Dimensions

| Dimension | Fichier | Description |
|---|---|---|
| `dim_tactics` | `data/warehouse/dim_tactics.csv` | 14 tactiques ATT&CK |
| `dim_techniques` | `data/warehouse/dim_techniques.csv` | 858 techniques et sous-techniques |
| `dim_groups` | `data/warehouse/dim_groups.csv` | ~170 groupes APT |
| `dim_platforms` | `data/warehouse/dim_platforms.csv` | ~12 plateformes ciblées |

> **Note** : Les noms `dim_*` et `fact_*` désignent à la fois les rôles logiques dans le modèle et les noms physiques des fichiers CSV/Parquet du projet.

---

## 5. Relations entre les entités

Le modèle permet d'étudier les relations suivantes :

```
          Groupe APT
               │
               │ utilise (uses)
               ▼
        Technique ATT&CK
               │
               │ associée à
               ▼
           Tactique
               │
               │ cible
               ▼
          Plateforme
```

- Un groupe peut utiliser plusieurs techniques.
- Une technique peut être utilisée par plusieurs groupes.
- Une technique peut appartenir à plusieurs tactiques.
- Une technique peut cibler plusieurs plateformes.

Ces relations permettent des analyses multidimensionnelles dans Power BI.

---

## 6. Utilisation dans Power BI

Le modèle est exploité dans Power BI pour produire :

| Visuel | Table source | Champs utilisés |
|---|---|---|
| KPI Techniques | `dim_techniques` | `attack_id` (Nombre distinct) |
| KPI Tactiques | `top_tactics` | `tactic` (Nombre distinct) |
| KPI Groupes APT | `top_groups` | `group_id` (Nombre distinct) |
| KPI Plateformes | `top_platforms` | `platform` (Nombre distinct) |
| Top 10 Groupes APT | `top_groups` | `name`, `nb_techniques` |
| Top 10 Techniques | `top_techniques` | `name`, `nb_groupes` |
| Tactiques fréquentes | `top_tactics` | `tactic`, `nb_utilisations` |
| Répartition plateformes | `top_platforms` | `platform`, `nb_techniques` |
| Matrice ATT&CK | `attack_matrix` | `tactic`, `technique_name` |
| Techniques émergentes | `techniques_emergentes` | `attack_id`, `name`, `created` |
| Analyse APT | `apt_analysis` | `group_name`, `technique`, `tactic` |

**Filtres interactifs disponibles** : Tactic · Platform · APT Group · Technique

---

## 7. Flux global des données

```
MITRE ATT&CK (github.com/mitre/cti)
           │
           ▼
    JSON STIX 2.0
           │
           ▼  01_download_data.R
    Téléchargement
           │
           ▼  02_explore_data.R
      Exploration
           │
           ▼  03_parse_stix.R
  Tables brutes (data/processed/)
           │
           ▼  04_star_schema.R
  Schéma en étoile (data/warehouse/)
           │
           ▼  05_export_parquet.R
  Format Parquet (data/parquet/)
           │
           ▼  06_upload_s3.R
       AWS S3
           │
           ▼  07_transformations.R
Tables analytiques (data/analytics/)
           │
           ▼
     Power BI Desktop
           │
           ▼
   Dashboard interactif
```

---

## 8. Résumé des tables

| Table | Emplacement | Lignes (approx.) | Rôle |
|---|---|---|---|
| `tactics` | `data/processed/` | 14 | Extraction brute |
| `techniques` | `data/processed/` | 858 | Extraction brute |
| `groups` | `data/processed/` | ~170 | Extraction brute |
| `malware` | `data/processed/` | ~400 | Extraction brute |
| `relationships` | `data/processed/` | ~14 000 | Extraction brute |
| `technique_tactic` | `data/processed/` | ~1 090 | Extraction brute |
| `dim_tactics` | `data/warehouse/` | 14 | Dimension |
| `dim_techniques` | `data/warehouse/` | 858 | Dimension |
| `dim_groups` | `data/warehouse/` | ~170 | Dimension |
| `dim_platforms` | `data/warehouse/` | ~12 | Dimension |
| `fact_technique_utilisee_par_groupe` | `data/warehouse/` | ~8 000 | Fait |
| `bridge_technique_platform` | `data/warehouse/` | ~2 000 | Table pont |
| `top_groups` | `data/analytics/` | ~170 | Analytique |
| `top_techniques` | `data/analytics/` | ~490 | Analytique |
| `top_tactics` | `data/analytics/` | 14 | Analytique |
| `top_platforms` | `data/analytics/` | ~12 | Analytique |
| `techniques_actives` | `data/analytics/` | ~697 | Analytique |
| `techniques_emergentes` | `data/analytics/` | 50 | Analytique |
| `apt_analysis` | `data/analytics/` | ~500 | Analytique |

---

*Document généré dans le cadre du projet MITRE ATT&CK Data Engineering — Groupe 9 — 2025–2026*

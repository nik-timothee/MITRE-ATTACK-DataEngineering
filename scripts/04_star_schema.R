############################################################
# Projet : MITRE ATT&CK Data Engineering
# Script : 04_star_schema.R
# Objectif :
#   - Construire le schéma en étoile du projet
#   - Créer les tables de dimensions
#   - Créer la table de faits
#   - Sauvegarder les résultats dans data/warehouse
############################################################

# ==========================================================
# Chargement des bibliothèques
# ==========================================================

# Manipulation des données
library(dplyr)

# Lecture / écriture des fichiers CSV
library(readr)

# Manipulation des chaînes de caractères
library(stringr)

# Transformation des données
library(tidyr)

# ==========================================================
# Lecture des données extraites
# ==========================================================

cat("Chargement des données...\n")

tactics <- read_csv(
  "data/processed/tactics.csv",
  show_col_types = FALSE
)

techniques <- read_csv(
  "data/processed/techniques.csv",
  show_col_types = FALSE
)

groups <- read_csv(
  "data/processed/groups.csv",
  show_col_types = FALSE
)

relationships <- read_csv(
  "data/processed/relationships.csv",
  show_col_types = FALSE
)

# ==========================================================
# Création du dossier de sortie
# ==========================================================

dir.create(
  "data/warehouse",
  recursive = TRUE,
  showWarnings = FALSE
)

cat("Données chargées avec succès.\n\n")





# ==========================================================
# Construction des dimensions
# ==========================================================

cat("Construction des dimensions...\n")

# ----------------------------------------------------------
# Dimension : Tactiques
# ----------------------------------------------------------
# Chaque ligne représente une tactique ATT&CK.

dim_tactics <- tactics


# ----------------------------------------------------------
# Dimension : Techniques
# ----------------------------------------------------------
# Chaque ligne représente une technique ATT&CK.

dim_techniques <- techniques


# ----------------------------------------------------------
# Dimension : Groupes APT
# ----------------------------------------------------------
# Chaque ligne représente un groupe d'attaquants.

dim_groups <- groups


# ----------------------------------------------------------
# Dimension : Plateformes
# ----------------------------------------------------------
# Les plateformes sont actuellement stockées sous forme de
# texte dans la colonne "platforms" des techniques.
#
# Exemple :
# "Windows, Linux, macOS"
#
# devient :
#
# Windows
# Linux
# macOS
# ----------------------------------------------------------

dim_platforms <- techniques |>
  
  # Conserver uniquement la colonne contenant les plateformes
  select(platforms) |>
  
  # Supprimer les lignes vides
  filter(!is.na(platforms)) |>
  
  # Séparer les plateformes lorsqu'il y en a plusieurs
  separate_rows(platforms, sep = ",") |>
  
  # Supprimer les espaces inutiles
  mutate(
    platforms = str_trim(platforms)
  ) |>
  
  # Supprimer les doublons
  distinct() |>
  
  # Trier alphabétiquement
  arrange(platforms) |>
  
  # Créer un identifiant numérique
  mutate(
    platform_id = row_number()
  ) |>
  
  # Réorganiser les colonnes
  select(
    platform_id,
    platform_name = platforms
  )


cat("Dimensions créées avec succès.\n\n")



head(dim_platforms)

nrow(dim_platforms)




# ==========================================================
# Construction de la table de faits
# ==========================================================

cat("Construction de la table de faits...\n")

fact_technique_utilisee_par_groupe <- relationships |>
  
  # Conserver uniquement les relations "uses"
  filter(relation == "uses") |>
  
  # La source doit être un groupe APT
  filter(str_starts(source, "intrusion-set--")) |>
  
  # La cible doit être une technique
  filter(str_starts(target, "attack-pattern--")) |>
  
  # Renommer les colonnes
  transmute(
    
    group_id = source,
    
    technique_id = target
    
  ) |>
  
  # Supprimer les doublons éventuels
  distinct()

cat(
  "Table de faits créée :",
  nrow(fact_technique_utilisee_par_groupe),
  "relations.\n\n"
)






# ==========================================================
# Table de liaison Techniques <-> Plateformes
# ==========================================================

cat("Construction de la table Technique - Plateforme...\n")

bridge_technique_platform <- techniques |>
  
  # Conserver les colonnes utiles
  select(
    technique_id = id,
    platforms
  ) |>
  
  # Ignorer les techniques sans plateforme
  filter(!is.na(platforms)) |>
  
  # Une plateforme par ligne
  separate_rows(
    platforms,
    sep = ","
  ) |>
  
  # Nettoyer les espaces
  mutate(
    platform_name = str_trim(platforms)
  ) |>
  
  select(
    technique_id,
    platform_name
  ) |>
  
  # Associer chaque plateforme à son identifiant
  left_join(
    dim_platforms,
    by = "platform_name"
  ) |>
  
  select(
    technique_id,
    platform_id
  ) |>
  
  distinct()

cat(
  "Relations Technique - Plateforme :",
  nrow(bridge_technique_platform),
  "\n\n"
)






head(fact_technique_utilisee_par_groupe)

head(bridge_technique_platform)

nrow(fact_technique_utilisee_par_groupe)

nrow(bridge_technique_platform)






# ==========================================================
# Sauvegarde des dimensions et de la table de faits
# ==========================================================

cat("Sauvegarde des fichiers du Data Warehouse...\n")

# ----------------------------------------------------------
# Dimensions
# ----------------------------------------------------------

write_csv(
  dim_tactics,
  "data/warehouse/dim_tactics.csv"
)

write_csv(
  dim_techniques,
  "data/warehouse/dim_techniques.csv"
)

write_csv(
  dim_groups,
  "data/warehouse/dim_groups.csv"
)

write_csv(
  dim_platforms,
  "data/warehouse/dim_platforms.csv"
)

# ----------------------------------------------------------
# Table de faits
# ----------------------------------------------------------

write_csv(
  fact_technique_utilisee_par_groupe,
  "data/warehouse/fact_technique_utilisee_par_groupe.csv"
)

# ----------------------------------------------------------
# Table de liaison
# ----------------------------------------------------------

write_csv(
  bridge_technique_platform,
  "data/warehouse/bridge_technique_platform.csv"
)

cat("Tous les fichiers ont été sauvegardés.\n\n")





# ==========================================================
# Résumé du schéma en étoile
# ==========================================================

cat("\n=============================================\n")
cat("      SCHEMA EN ETOILE GENERE AVEC SUCCES\n")
cat("=============================================\n\n")

cat("Dimensions créées :\n")
cat("-------------------\n")
cat("Tactiques           :", nrow(dim_tactics), "\n")
cat("Techniques          :", nrow(dim_techniques), "\n")
cat("Groupes APT         :", nrow(dim_groups), "\n")
cat("Plateformes         :", nrow(dim_platforms), "\n\n")

cat("Tables relationnelles :\n")
cat("------------------------\n")
cat("Techniques ↔ Plateformes :", nrow(bridge_technique_platform), "\n")
cat("Groupes ↔ Techniques     :", nrow(fact_technique_utilisee_par_groupe), "\n\n")

cat("Les fichiers ont été enregistrés dans :\n")
cat("data/warehouse/\n")

cat("\nFin du script 04_star_schema.R\n")





list.files("data/warehouse")
dim(dim_tactics)

dim(dim_techniques)

dim(dim_groups)

dim(dim_platforms)

dim(fact_technique_utilisee_par_groupe)

dim(bridge_technique_platform)
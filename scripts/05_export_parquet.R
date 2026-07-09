############################################################
# Projet : MITRE ATT&CK Data Engineering
# Script : 05_export_parquet.R
# Objectif :
#   - Convertir les tables du Data Warehouse
#     du format CSV vers le format Parquet
############################################################

# ==========================================================
# Chargement des bibliothèques
# ==========================================================

# Lecture des fichiers CSV
library(readr)

# Écriture des fichiers Parquet
library(arrow)

# ==========================================================
# Création du dossier de sortie
# ==========================================================

dir.create(
  "data/parquet",
  recursive = TRUE,
  showWarnings = FALSE
)

cat("Conversion des fichiers CSV vers Parquet...\n\n")


# ==========================================================
# Lecture des tables du Data Warehouse
# ==========================================================

dim_tactics <- read_csv(
  "data/warehouse/dim_tactics.csv",
  show_col_types = FALSE
)

dim_techniques <- read_csv(
  "data/warehouse/dim_techniques.csv",
  show_col_types = FALSE
)

dim_groups <- read_csv(
  "data/warehouse/dim_groups.csv",
  show_col_types = FALSE
)

dim_platforms <- read_csv(
  "data/warehouse/dim_platforms.csv",
  show_col_types = FALSE
)

fact_technique_utilisee_par_groupe <- read_csv(
  "data/warehouse/fact_technique_utilisee_par_groupe.csv",
  show_col_types = FALSE
)

bridge_technique_platform <- read_csv(
  "data/warehouse/bridge_technique_platform.csv",
  show_col_types = FALSE
)

cat("Toutes les tables ont été chargées.\n\n")


# ==========================================================
# Export des tables au format Parquet
# ==========================================================

write_parquet(
  dim_tactics,
  "data/parquet/dim_tactics.parquet"
)

write_parquet(
  dim_techniques,
  "data/parquet/dim_techniques.parquet"
)

write_parquet(
  dim_groups,
  "data/parquet/dim_groups.parquet"
)

write_parquet(
  dim_platforms,
  "data/parquet/dim_platforms.parquet"
)

write_parquet(
  fact_technique_utilisee_par_groupe,
  "data/parquet/fact_technique_utilisee_par_groupe.parquet"
)

write_parquet(
  bridge_technique_platform,
  "data/parquet/bridge_technique_platform.parquet"
)

cat("Tous les fichiers ont été convertis en Parquet.\n\n")


# ==========================================================
# Résumé
# ==========================================================

cat("=========================================\n")
cat(" Conversion vers le format Parquet OK\n")
cat("=========================================\n\n")

cat("Fichiers créés :\n")
cat("----------------\n")
cat("dim_tactics.parquet\n")
cat("dim_techniques.parquet\n")
cat("dim_groups.parquet\n")
cat("dim_platforms.parquet\n")
cat("fact_technique_utilisee_par_groupe.parquet\n")
cat("bridge_technique_platform.parquet\n\n")

cat("Emplacement : data/parquet/\n")











list.files("data/parquet")

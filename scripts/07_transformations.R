############################################################
# Projet : MITRE ATT&CK Data Engineering
# Script : 07_transformations.R
# Objectif :
#   Réaliser les transformations analytiques demandées
#   pour le tableau de bord Power BI.
############################################################

# ==========================================================
# Chargement des bibliothèques
# ==========================================================

library(readr)
library(dplyr)
library(stringr)

cat("Chargement des données...\n")



dir.create(
  "data/analytics",
  recursive = TRUE,
  showWarnings = FALSE
)




dim_groups <- read_csv(
  "data/warehouse/dim_groups.csv",
  show_col_types = FALSE
)

dim_techniques <- read_csv(
  "data/warehouse/dim_techniques.csv",
  show_col_types = FALSE
)

dim_tactics <- read_csv(
  "data/warehouse/dim_tactics.csv",
  show_col_types = FALSE
)

dim_platforms <- read_csv(
  "data/warehouse/dim_platforms.csv",
  show_col_types = FALSE
)

fact <- read_csv(
  "data/warehouse/fact_technique_utilisee_par_groupe.csv",
  show_col_types = FALSE
)

bridge <- read_csv(
  "data/warehouse/bridge_technique_platform.csv",
  show_col_types = FALSE
)

technique_tactic <- read_csv(
  "data/processed/technique_tactic.csv",
  show_col_types = FALSE
)

cat("Toutes les tables sont chargées.\n\n")






cat("Calcul du nombre de techniques par groupe...\n")

top_groups <- fact |>
  
  group_by(group_id) |>
  
  summarise(
    nb_techniques = n_distinct(technique_id),
    .groups = "drop"
  ) |>
  
  left_join(
    dim_groups,
    by = c("group_id" = "id")
  ) |>
  
  arrange(desc(nb_techniques))

write_csv(
  top_groups,
  "data/analytics/top_groups.csv"
)

cat("Analyse des groupes terminée.\n\n")





head(top_groups)

dim(top_groups)






# ==========================================================
# Calcul des tactiques les plus utilisées
# ==========================================================

cat("Calcul des tactiques les plus utilisées...\n")

top_tactics <- fact |>
  
  inner_join(
    technique_tactic,
    by = c("technique_id")
  ) |>
  
  group_by(tactic) |>
  
  summarise(
    
    nb_utilisations = n(),
    
    nb_groupes = n_distinct(group_id),
    
    .groups = "drop"
    
  ) |>
  
  arrange(desc(nb_utilisations))

write_csv(
  
  top_tactics,
  
  "data/analytics/top_tactics.csv"
  
)

cat("Analyse des tactiques terminée.\n\n")






head(top_tactics)

dim(top_tactics)




# ==========================================================
# Calcul des plateformes les plus ciblées
# ==========================================================
cat("Calcul des plateformes les plus ciblées...\n")

top_platforms <- dim_techniques |>
  # Ignorer les techniques sans plateforme
  filter(!is.na(platforms)) |>
  # Séparer les plateformes (ex: "Windows, Linux" → deux lignes)
  mutate(platform = strsplit(platforms, ", ")) |>
  tidyr::unnest(platform) |>
  group_by(platform) |>
  summarise(
    nb_techniques = n_distinct(id),
    .groups = "drop"
  ) |>
  arrange(desc(nb_techniques))

write_csv(
  top_platforms,
  "data/analytics/top_platforms.csv"
)

cat("Analyse des plateformes terminée.\n\n")




head(top_platforms)

dim(top_platforms)




# ==========================================================
# Calcul des techniques les plus utilisées
# ==========================================================

cat("Calcul des techniques les plus répandues...\n")

top_techniques <- fact |>
  
  group_by(technique_id) |>
  
  summarise(
    
    nb_groupes = n_distinct(group_id),
    
    .groups = "drop"
    
  ) |>
  
  left_join(
    
    dim_techniques,
    
    by = c("technique_id" = "id")
    
  ) |>
  
  arrange(desc(nb_groupes))

write_csv(
  
  top_techniques,
  
  "data/analytics/top_techniques.csv"
  
)

cat("Analyse des techniques terminée.\n\n")









# ==========================================================
# Résumé des transformations
# ==========================================================

cat("\n=============================================\n")
cat("   TRANSFORMATIONS ANALYTIQUES TERMINEES\n")
cat("=============================================\n\n")

cat("Fichiers générés :\n")
cat("------------------\n")
cat("top_groups.csv\n")
cat("top_tactics.csv\n")
cat("top_platforms.csv\n\n")
cat("top_techniques.csv\n")

cat("Emplacement : data/analytics/\n\n")

cat("Nombre de groupes analysés      :", nrow(top_groups), "\n")
cat("Nombre de tactiques analysées   :", nrow(top_tactics), "\n")
cat("Nombre de plateformes analysées :", nrow(top_platforms), "\n")
cat("Nombre de techniques analysées :", nrow(top_techniques), "\n")


list.files("data/analytics")





head(top_techniques)

dim(top_techniques)
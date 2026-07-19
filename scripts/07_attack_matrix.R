############################################################
# Projet : MITRE ATT&CK Data Engineering
# Script : 07_attack_matrix.R
#
# Objectif :
#   - Construire la matrice ATT&CK
#   - Associer chaque technique à sa (ou ses) tactique(s)
#   - Générer un fichier attack_matrix.csv
############################################################


# ==========================================================
# Chargement des bibliothèques
# ==========================================================

library(jsonlite)
library(dplyr)
library(readr)


# ==========================================================
# Chargement du fichier MITRE ATT&CK
# ==========================================================

mitre <- fromJSON(
  "data/raw/enterprise-attack.json",
  simplifyVector = FALSE
)

objects <- mitre$objects


# ==========================================================
# Sélection des techniques ATT&CK
# ==========================================================

attack_patterns <- Filter(
  function(x) x$type == "attack-pattern",
  objects
)


# ==========================================================
# Initialisation du tableau résultat
# ==========================================================

attack_matrix <- data.frame()


# ==========================================================
# Parcours de toutes les techniques
# ==========================================================

for (technique in attack_patterns) {
  
  ##########################################################
  # Extraction de l'identifiant ATT&CK
  ##########################################################
  
  attack_id <- NA
  
  if (!is.null(technique$external_references)) {
    
    for (ref in technique$external_references) {
      
      if (!is.null(ref$external_id)) {
        
        attack_id <- ref$external_id
        break
        
      }
      
    }
    
  }
  
  
  ##########################################################
  # Nom de la technique
  ##########################################################
  
  technique_name <- technique$name
  
  
  ##########################################################
  # Une technique peut appartenir à plusieurs tactiques.
  ##########################################################
  
  if (!is.null(technique$kill_chain_phases)) {
    
    for (phase in technique$kill_chain_phases) {
      
      ######################################################
      # On conserve uniquement les phases MITRE ATT&CK
      ######################################################
      
      if (phase$kill_chain_name == "mitre-attack") {
        
        ligne <- data.frame(
          
          tactic = phase$phase_name,
          
          technique_id = attack_id,
          
          technique_name = technique_name,
          
          stringsAsFactors = FALSE
          
        )
        
        attack_matrix <- bind_rows(
          attack_matrix,
          ligne
        )
        
      }
      
    }
    
  }
  
}


# ==========================================================
# Suppression des doublons éventuels
# ==========================================================

attack_matrix <- attack_matrix |>
  
  distinct()


# ==========================================================
# Tri des résultats
# ==========================================================

attack_matrix <- attack_matrix |>
  
  arrange(
    tactic,
    technique_id
  )


# ==========================================================
# Création du dossier analytics
# ==========================================================

dir.create(
  "data/analytics",
  recursive = TRUE,
  showWarnings = FALSE
)


# ==========================================================
# Sauvegarde du résultat
# ==========================================================

write_csv(
  
  attack_matrix,
  
  "data/analytics/attack_matrix.csv"
  
)


# ==========================================================
# Résumé
# ==========================================================

cat("\n=========================================\n")

cat("Matrice ATT&CK créée avec succès\n")

cat("=========================================\n")

cat("Nombre de lignes :", nrow(attack_matrix), "\n")

cat("Nombre de tactiques :", length(unique(attack_matrix$tactic)), "\n")

cat("Nombre de techniques :", length(unique(attack_matrix$technique_id)), "\n")
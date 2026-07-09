############################################################
# Projet : MITRE ATT&CK Data Engineering
# Script : 03_parse_stix.R
# Objectif :
#   - Lire le fichier JSON STIX 2.0 de MITRE ATT&CK
#   - Extraire les principales entités du référentiel
#   - Les convertir en tables structurées (DataFrames)
#   - Sauvegarder les résultats au format CSV
############################################################

# ==========================================================
# Chargement des bibliothèques nécessaires
# ==========================================================

# Lecture des fichiers JSON
library(jsonlite)

# Manipulation des données
library(dplyr)

# Lecture / écriture des fichiers CSV
library(readr)


# ==========================================================
# Chargement du fichier JSON MITRE ATT&CK
# ==========================================================

# Le paramètre simplifyVector = FALSE permet de conserver
# la structure originale du fichier STIX sous forme de listes.
mitre <- fromJSON(
  "data/raw/enterprise-attack.json",
  simplifyVector = FALSE
)

# Les objets STIX (techniques, tactiques, groupes, etc.)
# sont tous contenus dans la liste "objects".
objects <- mitre$objects


# ==========================================================
# Création du dossier de sortie
# ==========================================================

# Création du dossier data/processed s'il n'existe pas.
dir.create(
  "data/processed",
  recursive = TRUE,
  showWarnings = FALSE
)


# ==========================================================
# Extraction des tactiques (x-mitre-tactic)
# ==========================================================

# Chaque objet dont le type est "x-mitre-tactic"
# représente une tactique ATT&CK.

tactics <- Filter(function(x)
  x$type == "x-mitre-tactic",
  objects
) |>
  
  lapply(function(x){
    
    data.frame(
      
      # Identifiant unique STIX
      id = x$id,
      
      # Nom de la tactique
      name = x$name,
      
      # Nom court utilisé par ATT&CK
      short_name = x$x_mitre_shortname,
      
      # Description complète
      description = ifelse(
        is.null(x$description),
        NA,
        x$description
      )
      
    )
    
  }) |>
  
  bind_rows()


# ==========================================================
# Extraction des techniques (attack-pattern)
# ==========================================================

# Les techniques et sous-techniques ATT&CK sont stockées
# dans les objets de type "attack-pattern".

techniques <- Filter(function(x) {
  x$type == "attack-pattern"
}, objects) |>
  
  lapply(function(x) {
    
    # ------------------------------------------------------
    # Extraction de l'identifiant ATT&CK (ex : T1059)
    # ------------------------------------------------------
    
    attack_id <- NA
    
    if (!is.null(x$external_references)) {
      
      for (ref in x$external_references) {
        
        if (!is.null(ref$external_id)) {
          
          attack_id <- ref$external_id
          break
          
        }
        
      }
      
    }
    
    # ------------------------------------------------------
    # Extraction des plateformes concernées
    # ------------------------------------------------------
    # Une technique peut cibler plusieurs plateformes.
    # Elles sont regroupées dans une seule chaîne de caractères.
    
    platforms <- NA
    
    if (!is.null(x$x_mitre_platforms)) {
      
      platforms <- paste(
        unlist(x$x_mitre_platforms),
        collapse = ", "
      )
      
    }
    
    # ------------------------------------------------------
    # Création d'une ligne du DataFrame
    # ------------------------------------------------------
    
    data.frame(
      
      # Identifiant STIX
      id = x$id,
      
      # Identifiant ATT&CK (Txxxx)
      attack_id = attack_id,
      
      # Nom de la technique
      name = x$name,
      
      # Description
      description = ifelse(
        is.null(x$description),
        NA,
        x$description
      ),
      
      # Plateformes concernées
      platforms = platforms,
      
      # Technique révoquée ?
      revoked = isTRUE(x$revoked),
      
      # Technique obsolète ?
      deprecated = isTRUE(x$x_mitre_deprecated),
      
      stringsAsFactors = FALSE
      
    )
    
  }) |>
  
  bind_rows()


# ==========================================================
# Extraction de la relation Technique ↔ Tactique
# ==========================================================

technique_tactic <- list()

for (x in Filter(function(o) o$type == "attack-pattern", objects)) {
  
  # Récupération de l'identifiant ATT&CK (Txxxx)
  attack_id <- NA
  
  if (!is.null(x$external_references)) {
    
    for (ref in x$external_references) {
      
      if (!is.null(ref$external_id)) {
        
        attack_id <- ref$external_id
        break
        
      }
      
    }
    
  }
  
  # Une technique peut appartenir à plusieurs tactiques
  if (!is.null(x$kill_chain_phases)) {
    
    for (phase in x$kill_chain_phases) {
      
      if (!is.null(phase$phase_name)) {
        
        technique_tactic[[length(technique_tactic) + 1]] <- data.frame(
          
          technique_id = x$id,
          
          attack_id = attack_id,
          
          tactic = phase$phase_name,
          
          stringsAsFactors = FALSE
          
        )
        
      }
      
    }
    
  }
  
}

technique_tactic <- bind_rows(technique_tactic)


# ==========================================================
# Extraction des groupes APT (intrusion-set)
# ==========================================================

# Les groupes d'attaquants (APT) sont représentés
# par des objets de type "intrusion-set".

groups <- Filter(function(x){
  x$type == "intrusion-set"
}, objects) |>
  
  lapply(function(x){
    
    data.frame(
      
      # Identifiant STIX
      id = x$id,
      
      # Nom du groupe
      name = x$name,
      
      # Alias éventuels — certains groupes n'en ont pas (NULL)
      # ifelse évite l'erreur produite par unlist(NULL)
      aliases = ifelse(
        is.null(x$aliases),
        NA,
        paste(
          unlist(x$aliases),
          collapse = ", "
        )
      )
      
    )
    
  }) |>
  
  bind_rows()


# ==========================================================
# Extraction des logiciels malveillants (malware)
# ==========================================================

# Les objets de type "malware" représentent
# les logiciels malveillants référencés dans ATT&CK.

malware <- Filter(function(x){
  x$type == "malware"
}, objects) |>
  
  lapply(function(x){
    
    data.frame(
      
      # Identifiant STIX
      id = x$id,
      
      # Nom du malware — certains objets STIX n'ont pas de champ name
      # ifelse retourne NA dans ce cas pour éviter une erreur
      name = ifelse(
        is.null(x$name),
        NA,
        x$name
      )
      
    )
    
  }) |>
  
  bind_rows()


# ==========================================================
# Extraction des relations STIX
# ==========================================================

# Les relations constituent l'élément central du modèle.
# Elles permettent notamment de savoir :
# - quel groupe utilise quelle technique
# - quel malware utilise quelle technique
# - quelles techniques sont liées à quelles tactiques
# etc.

relationships <- Filter(function(x){
  x$type == "relationship"
}, objects) |>
  
  lapply(function(x){
    
    data.frame(
      
      # Objet source
      source = x$source_ref,
      
      # Objet cible
      target = x$target_ref,
      
      # Type de relation
      relation = x$relationship_type
      
    )
    
  }) |>
  
  bind_rows()


# ==========================================================
# Sauvegarde des données extraites
# ==========================================================

cat("Sauvegarde des fichiers CSV...\n")

write_csv(
  tactics,
  "data/processed/tactics.csv"
)

write_csv(
  techniques,
  "data/processed/techniques.csv"
)

write_csv(
  groups,
  "data/processed/groups.csv"
)

write_csv(
  malware,
  "data/processed/malware.csv"
)

write_csv(
  relationships,
  "data/processed/relationships.csv"
)

write_csv(
  technique_tactic,
  "data/processed/technique_tactic.csv"
)


# ==========================================================
# Affichage d'un résumé de l'extraction
# ==========================================================

cat("\n=====================================\n")
cat("Extraction terminée avec succès.\n")
cat("=====================================\n")

cat("Nombre de tactiques               :", nrow(tactics), "\n")
cat("Nombre de techniques              :", nrow(techniques), "\n")
cat("Nombre de groupes APT             :", nrow(groups), "\n")
cat("Nombre de malwares                :", nrow(malware), "\n")
cat("Nombre de relations               :", nrow(relationships), "\n")
cat("Relations Technique ↔ Tactique    :", nrow(technique_tactic), "\n")




head(technique_tactic)

dim(technique_tactic)


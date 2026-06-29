############################################################
# Projet : MITRE ATT&CK Data Engineering
# Script : 02_explore_data.R
# Objectif : Explorer la structure des données STIX 2.0
# Auteur : nik-timothee
############################################################

library(jsonlite)
library(dplyr)

# -----------------------------
# Chargement du fichier Enterprise
# -----------------------------

file_path <- "data/raw/enterprise-attack.json"

mitre <- fromJSON(file_path, simplifyVector = FALSE)

cat("Fichier chargé avec succès.\n\n")

# -----------------------------
# Informations générales
# -----------------------------

cat("Type :", mitre$type, "\n")
cat("ID :", mitre$id, "\n")
cat("Nombre total d'objets :", length(mitre$objects), "\n\n")

# -----------------------------
# Structure générale
# -----------------------------

cat("Structure du bundle STIX :\n")
str(mitre, max.level = 1)

cat("\n-----------------------------------\n")

# -----------------------------
# Types d'objets présents
# -----------------------------

object_types <- sapply(
  mitre$objects,
  function(x) x$type
)

table_types <- sort(table(object_types), decreasing = TRUE)

cat("Répartition des types d'objets :\n\n")
print(table_types)

cat("\n-----------------------------------\n")

# -----------------------------
# Aperçu du premier objet
# -----------------------------

cat("Premier objet du fichier :\n\n")
str(mitre$objects[[1]], max.level = 2)

cat("\n-----------------------------------\n")

# -----------------------------
# Exemples de noms
# -----------------------------

names_list <- sapply(
  mitre$objects,
  function(x){
    
    if(!is.null(x$name))
      return(x$name)
    
    return(NA)
  }
)

cat("Quelques objets présents :\n\n")

print(na.omit(head(names_list,20)))
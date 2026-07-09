############################################################
# Projet : MITRE ATT&CK Data Engineering
# Script : 06_upload_s3.R
# Objectif :
#   - Envoyer les fichiers Parquet vers AWS S3
#   - Les stocker dans "processed/parquet/" du bucket
# Note : Les credentials sont chargés automatiquement
#        depuis le fichier .Renviron 
############################################################

library(aws.s3)

# ==========================================================
# Chargement de la configuration AWS depuis .Renviron
# Les clés sont lues automatiquement par aws.s3
# ==========================================================

bucket_name <- Sys.getenv("AWS_BUCKET_NAME")

# Vérification que la configuration est bien chargée
cat("Configuration AWS\n")
cat("-----------------\n")
cat("Région :", Sys.getenv("AWS_DEFAULT_REGION"), "\n")
cat("Bucket :", Sys.getenv("AWS_BUCKET_NAME"), "\n\n")

# ==========================================================
# Liste des fichiers à uploader
# ==========================================================

files <- c(
  "data/parquet/dim_tactics.parquet",
  "data/parquet/dim_techniques.parquet",
  "data/parquet/dim_groups.parquet",
  "data/parquet/dim_platforms.parquet",
  "data/parquet/fact_technique_utilisee_par_groupe.parquet",
  "data/parquet/bridge_technique_platform.parquet"
)

# ==========================================================
# Upload des fichiers vers S3
# ==========================================================

cat("Début de l'upload...\n\n")

for (file in files) {
  
  # Vérifier que le fichier existe localement avant d'uploader
  if (!file.exists(file)) {
    cat("  IGNORÉ (fichier introuvable) :", file, "\n")
    next
  }
  
  # Destination dans le bucket : processed/parquet/nom_fichier.parquet
  s3_destination <- paste0("processed/parquet/", basename(file))
  
  cat("  Upload :", basename(file), "->", s3_destination, "...")
  
  put_object(
    file   = file,
    object = s3_destination,
    bucket = bucket_name
  )
  
  cat(" OK\n")
  
}

# ==========================================================
# Vérification des fichiers uploadés dans "processed/parquet/"
# ==========================================================

cat("\nVérification du contenu du dossier processed/parquet/ sur S3...\n\n")

contenu <- get_bucket_df(bucket_name, prefix = "processed/parquet/")

if (nrow(contenu) == 0) {
  cat("Aucun fichier trouvé dans processed/parquet/\n")
} else {
  for (i in seq_len(nrow(contenu))) {
    cat(sprintf("  - %s (%.1f Ko)\n",
                contenu$Key[i],
                as.numeric(contenu$Size[i]) / 1024
    ))
  }
}

# ==========================================================
# Résumé final
# ==========================================================

cat("\n=====================================\n")
cat("Upload terminé avec succès.\n")
cat("Bucket  :", bucket_name, "\n")
cat("Dossier : processed/parquet/\n")
cat("Fichiers:", nrow(contenu), "fichiers présents\n")
cat("=====================================\n")




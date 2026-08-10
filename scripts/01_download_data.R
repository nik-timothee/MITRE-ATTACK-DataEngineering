############################################################
# Projet : MITRE ATT&CK Data Engineering
# Script : 01_download_data.R
# Objectif : Télécharger les données MITRE ATT&CK
# Auteur : nik-timothee
############################################################

# -----------------------------
# Création du dossier de données
# -----------------------------

raw_dir <- "data/raw"

if (!dir.exists(raw_dir)) {
  dir.create(raw_dir, recursive = TRUE)
  cat("Dossier créé :", raw_dir, "\n")
} else {
  cat("Le dossier existe déjà :", raw_dir, "\n")
}

# -----------------------------
# Liste des fichiers à télécharger
# -----------------------------

files <- c(
  enterprise = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
  mobile     = "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
  ics        = "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json"
)

# -----------------------------
# Téléchargement
# -----------------------------
    
for(name in names(files)){
  
  destination <- file.path(raw_dir,
                           paste0(name, "-attack.json"))
  
  cat("---------------------------------\n")
  cat("Téléchargement :", name, "\n")
  
  download.file(
    url = files[name],
    destfile = destination,
    mode = "wb"
  )
  
  if(file.exists(destination)){
    cat("Téléchargement réussi\n")
  }else{
    cat("Échec du téléchargement\n")
  }
}

cat("---------------------------------\n")
cat("Tous les téléchargements sont terminés.\n")
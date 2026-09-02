# BifProtect Testeur V3.2 — SIREN

## Objet
Prototype de qualification d'une entreprise et de son site marchand à partir du **SIREN**.

## Entrées
- SIREN : 9 chiffres.
- Site marchand : le champ est prérempli avec `https://www.`. L'utilisateur peut saisir le reste du domaine. Le backend accepte également un domaine saisi sans protocole et lui applique `https://www.`.

## Rattachement domaine ↔ entreprise
Le rattachement est **VÉRIFIÉ** dans deux cas principaux :
1. le SIREN apparaît dans une preuve juridique publiée sur le domaine organisationnel contrôlé ;
2. une page juridique du domaine identifie explicitement la raison sociale correspondant au SIREN comme exploitant, vendeur, éditeur, responsable du traitement ou propriétaire. Le SIREN n'a donc pas besoin d'être imprimé dans chaque CGV/mention légale.

Les sous-domaines officiels sont acceptés uniquement lorsqu'ils appartiennent au même domaine organisationnel ; l'appartenance DNS seule ne constitue pas une preuve.

## Décision
- Blocage juridique : `NON ÉLIGIBLE`.
- Contrôle complémentaire : `ÉLIGIBLE SOUS RÉSERVE`, souscription possible mais validation définitive en attente du justificatif.
- Aucun blocage ni complémentaire et score >= 80 : `ÉLIGIBLE`.

## Affichage
Seuls les contrôles non conformes, inconnus ou complémentaires sont affichés. Les contrôles conformes restent pris en compte dans le calcul mais sont masqués.

## Déploiement Render
- Build : `python -m compileall .`
- Start : `python server.py`
- Health : `/health`

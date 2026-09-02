# BifProtect Testeur V3.8 — SIREN

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
- Score < 60 : `CONTRÔLE COMPLÉMENTAIRE`.
- Score 60–79 : `SURVEILLANCE RENFORCÉE`.
- Score >= 80 avec complément documentaire : `ÉLIGIBLE SOUS RÉSERVE`.
- Score >= 80 sans complément : `ÉLIGIBLE`.

Un accès automatisé protégé n'est pas assimilé à une indisponibilité du site : les contrôles HTTP non mesurables ne sont pas pénalisés.

## Affichage
La synthèse utilisateur n'affiche pas la liste brute des contrôles techniques. Elle présente le score, le statut de qualification, le nombre de sujets techniques à corriger et les éventuels compléments documentaires. Les contrôles conformes et les détails techniques restent utilisés par le moteur mais sont masqués de la synthèse.

## Déploiement Render
- Build : `python -m compileall .`
- Start : `python server.py`
- Health : `/health`


Optimisation V3.8 : vérification du rattachement domaine plus ciblée et parallélisée, sans exploration automatique des sous-domaines arbitraires ni sitemap.

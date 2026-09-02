# BifProtect Testeur V2

Prototype de qualification d'un site marchand par **identité entreprise + statut juridique + rattachement domaine/SIRET + sécurité technique**.

## Contrôles V2

### Identité / statut
- SIRET exact recherché via l'API publique Recherche d'entreprises (SIRENE).
- SIREN / dénomination.
- état administratif de l'unité légale.
- état administratif de l'établissement correspondant au SIRET.
- recherche des annonces pertinentes BODACC pour détecter radiation et procédures collectives.

### Rattachement entreprise ↔ domaine
Le moteur ouvre la page demandée puis recherche des pages de type :
- mentions légales ;
- informations légales ;
- CGV ;
- contact ;
- à propos / about ;
- legal notice.

Le rattachement est **VERIFIE** uniquement lorsqu'une preuve forte est trouvée : SIRET ou SIREN de l'entreprise dans une page du site. Une simple correspondance de marque ou de nom est classée **PROBABLE** et ne suffit pas pour l'éligibilité.

### Sécurité technique
- DNS / IPv4 / IPv6
- accessibilité
- HTTPS
- certificat TLS
- HSTS
- CSP
- X-Content-Type-Options
- X-Frame-Options
- URL finale

## Règle d'éligibilité

Le score technique ne peut pas compenser un problème d'identité juridique ou de rattachement.

Une société non active, un établissement SIRET fermé, une radiation signalée, une liquidation judiciaire signalée ou un rattachement domaine/SIRET non établi empêchent l'éligibilité.

Le redressement judiciaire et la sauvegarde déclenchent une **surveillance renforcée** plutôt qu'une exclusion automatique.

Si le contrôle BODACC est indisponible, BifProtect ne conclut pas à tort que l'entreprise est saine : le résultat devient **CONTRÔLE COMPLÉMENTAIRE**.

## Sources de données

- API publique Recherche d'entreprises / données SIRENE : https://recherche-entreprises.api.gouv.fr/
- BODACC / DILA, API open data : https://bodacc-datadila.opendatasoft.com/api/explore/v2.1/
- Le RNE/INPI reste la source de référence pour les inscriptions au Registre national des entreprises ; l'intégration directe de l'API RNE nécessitera les identifiants techniques INPI lorsque ceux-ci seront disponibles pour l'application.

## Sécurité du testeur

- HTTPS obligatoire pour les cibles.
- Les IP privées, réservées et non publiques sont bloquées.
- Les redirections vers une cible non publique sont bloquées.
- Taille des pages web limitée.
- Aucun scan intrusif.
- Le service n'est pas un proxy généraliste.

## Déploiement Render

Le `render.yaml` utilise Python, le plan Free, `python -m compileall .`, `python server.py` et `/health`.

## Limite

BifProtect V2 est un prototype de qualification. Il ne constitue ni une certification de sécurité, ni un avis juridique, ni une garantie de solvabilité. Une absence d'annonce BODACC ne doit pas être interprétée comme une garantie absolue d'absence de difficulté.

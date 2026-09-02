# BifProtect Testeur V2.9

Prototype de qualification non intrusive d'un site marchand à partir d'un **SIREN** et d'une URL.

## Identifiant métier

BifProtect qualifie désormais l'**unité légale** identifiée par le SIREN. Aucun SIRET ni établissement précis n'est requis pour la décision d'éligibilité.

## Contrôles

1. Vérification de l'entreprise et de son état administratif via Recherche d'entreprises.
2. Recherche BODACC/DILA des radiations et procédures collectives liées au SIREN.
3. Vérification du rattachement **SIREN ↔ domaine**.
4. Contrôles DNS, accessibilité HTTPS, TLS et en-têtes de sécurité.

### Rattachement du domaine

Le lien est **Vérifié** lorsqu'un SIREN est retrouvé comme preuve directe dans une page ou un document juridique accessible depuis le domaine contrôlé.

La recherche couvre :
- le domaine saisi et `www` ;
- les sous-domaines du même domaine organisationnel ;
- les pages de mentions légales, CGV, contact et pages institutionnelles ;
- les PDF juridiques ;
- les liens légaux/PDF découverts dans les pages ;
- les URLs légales découvertes via `robots.txt` / sitemap.

Un domaine tiers n'est jamais suivi comme preuve. Un sous-domaine ne devient une preuve que si le SIREN y est effectivement retrouvé.

## Décisions

- **NON ÉLIGIBLE** : condition juridique bloquante (entreprise cessée, radiation détectée, liquidation judiciaire en cours, etc.).
- **ÉLIGIBLE SOUS RÉSERVE** : souscription possible, mais un justificatif reste nécessaire avant validation définitive.
- **ÉLIGIBLE** : aucun blocage ni complément requis et score technique suffisant.

Le score technique n'est pas une certification de sécurité.

## Affichage

L'interface affiche le score et la décision, puis **uniquement les contrôles non conformes, à vérifier, complémentaires ou bloquants**. Les contrôles conformes sont masqués.

## Sources publiques

- Recherche d'entreprises : https://recherche-entreprises.api.gouv.fr/
- BODACC / DILA : https://bodacc-datadila.opendatasoft.com/
- RNE / INPI : https://data.inpi.fr/

L'API RNE/INPI peut être intégrée ultérieurement avec les identifiants techniques INPI afin de renforcer le contrôle des observations, radiations et procédures collectives.

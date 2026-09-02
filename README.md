# BifProtect Testeur V2.1

Prototype de qualification non intrusive d'un site marchand à partir d'un SIRET et d'une URL.

## Logique métier

1. Vérification de l'entreprise et du SIRET via l'API publique Recherche d'entreprises.
2. Vérification de l'état administratif de l'entreprise et de l'établissement correspondant.
3. Recherche des annonces BODACC/DILA liées au SIREN pour détecter radiation et procédures collectives.
4. Recherche non intrusive d'indices de rattachement entre le domaine et le SIREN/SIRET (mentions légales, CGV, contact et pages proches).
5. Contrôles DNS, accessibilité HTTPS, TLS et en-têtes de sécurité.

## Décisions

- **NON ÉLIGIBLE** : condition juridique bloquante (entreprise cessée, établissement fermé, radiation détectée, liquidation judiciaire, etc.).
- **ÉLIGIBLE SOUS RÉSERVE** : la souscription reste possible, mais un justificatif du lien entre l'entreprise et le domaine doit être fourni avant validation définitive.
- **ÉLIGIBLE** : contrôles automatisés satisfaisants, aucun complément requis.

Le score technique n'est pas une certification de sécurité.

## Sources publiques

- Recherche d'entreprises : https://recherche-entreprises.api.gouv.fr/
- BODACC / DILA : https://bodacc-datadila.opendatasoft.com/
- RNE / INPI : https://data.inpi.fr/

L'API RNE/INPI peut être intégrée ultérieurement avec les identifiants techniques INPI afin de renforcer le contrôle des observations, radiations et procédures collectives.

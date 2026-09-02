# BifProtect Testeur V2.7

Prototype de qualification non intrusive d'un site marchand à partir d'un SIREN et d'une URL.

## Logique métier

1. Vérification de l'entreprise et du SIREN via l'API publique Recherche d'entreprises.
2. Vérification de l'état administratif de l'entreprise et de l'établissement correspondant.
3. Recherche des annonces BODACC/DILA liées au SIREN pour détecter radiation et procédures collectives.
4. Recherche non intrusive d'indices de rattachement entre le domaine et le SIREN/SIREN (mentions légales, CGV, contact et pages proches).
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


### Affichage V2.7
L’interface n’affiche que le score, la décision et les contrôles non conformes, à vérifier ou complémentaires. Les contrôles conformes et leurs preuves positives sont masqués.


## V2.7 — règles renforcées
- Affichage utilisateur limité au score, à la décision et aux contrôles non conformes / à vérifier / complémentaires / bloquants.
- Les contrôles conformes ne sont pas affichés dans les tableaux.
- Priorité stricte des garde-fous juridiques sur les contrôles complémentaires.
- Une entreprise cessée reste bloquante même si le SIREN exact n'est pas confirmé.
- Un établissement fermé est bloquant ; un état d'établissement inconnu est complémentaire.
- Une décision complémentaire permet la souscription mais impose un justificatif avant validation définitive.


### V2.7 — rattachement domaine renforcé
Les mentions légales servies en PDF sont désormais analysées avec pypdf. Un SIREN/SIREN directement retrouvé dans un document légal du même domaine est classé « Vérifié », conformément à la règle métier.


## V2.8 — changement d'identifiant
BifProtect demande désormais le SIREN (9 chiffres) et non plus le SIRET. La qualification porte sur l'unité légale. Aucun établissement précis n'est imposé. Le lien domaine ↔ entreprise est recherché par preuve directe du SIREN.

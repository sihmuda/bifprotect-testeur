# BifProtect Testeur V1

Version propre et prête pour un déploiement Render.

## Contrôles
- SIRET / recherche d'entreprise publique
- DNS / IPv4 / IPv6
- accessibilité du site
- HTTPS obligatoire
- certificat TLS
- HSTS
- CSP
- X-Content-Type-Options
- X-Frame-Options
- autres en-têtes collectés
- score BifProtect explicable

Aucun CrowdSec et aucun scan intrusif dans cette V1.

## Déploiement Render

Le fichier `render.yaml` contient déjà :
- runtime Python
- plan free
- commande de compilation
- commande de démarrage
- health check `/health`

Le serveur écoute sur `0.0.0.0` et utilise la variable `PORT` fournie par Render.

## Sécurité

Le service n'accepte que des URLs HTTPS avec un nom de domaine public.
Les IP privées/réservées et les redirections vers des cibles non publiques sont bloquées afin d'éviter de transformer le service en relais vers des réseaux internes.

## Limite fonctionnelle

Le score V1 est un prototype. Il ne détecte pas toutes les vulnérabilités et ne constitue pas une certification de sécurité.

# Changelog

Format basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).

## [1.0.0] - 2026-05-08

### Ajouté
- Script initial `dirtyfrag-mitigate.sh`
- Mode `--check` : statut sans écriture
- Mode `--rollback` : retrait de la mitigation
- Mode `--force` : bypass du garde-fou IPSec
- Mode `--cluster "n1 n2 ..."` : déploiement multi-nodes via SSH
- Détection automatique d'IPSec actif via `ip xfrm`
- Drop du page cache pour éviter le reboot
- 4 vérifications post-mitigation
- Codes de sortie distincts pour intégration CI/Ansible

# dirtyfrag-mitigate

> Script bash de mitigation pour la vulnérabilité **Dirty Frag** (LPE Linux 0-day, divulguée le 7 mai 2026) sur hosts Proxmox VE.

[![Shell](https://img.shields.io/badge/shell-bash-4EAA25?logo=gnubash&logoColor=white)](#)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-mitigation_temporaire-orange)](#avertissement)

## Contexte

[**Dirty Frag**](https://github.com/V4bel/dirtyfrag) est une LPE 0-day Linux découverte par Hyunwoo Kim ([@v4bel](https://x.com/v4bel)). Elle chaîne deux vulnérabilités kernel — **xfrm-ESP Page-Cache Write** et **RxRPC Page-Cache Write** — qui permettent à un utilisateur non-privilégié d'écrire dans le page cache d'un fichier en lecture seule (ex. `/usr/bin/su`, `/etc/passwd`) pour obtenir root.

L'embargo a été cassé par un tiers le 7 mai 2026, avant que les distros aient pu shipper un patch coordonné. **Aucune CVE assignée, aucun patch distro disponible** au moment de la publication de ce script.

### Pourquoi spécifique à Proxmox VE ?

Sur un host Proxmox, le kernel est partagé avec tous les LXC. Une compromission depuis un container donne **root sur le host**. La mitigation doit donc être appliquée sur l'host PVE, pas dans les containers — ce script gère ce cas, avec les particularités du cluster (déploiement multi-nodes via SSH, garde-fou IPSec qu'on retrouve fréquemment sur des hyperviseurs).

Le script reste utilisable sur n'importe quel host Linux sous Debian/Ubuntu.

## Ce que fait le script

1. Détecte un IPSec actif (`ip xfrm state/policy`) — refuse d'appliquer si trouvé (sauf `--force`)
2. Crée `/etc/modprobe.d/dirtyfrag.conf` qui force `/bin/false` pour `esp4`, `esp6`, `rxrpc`
3. Décharge les modules en mémoire (`modprobe -r` puis `rmmod` en fallback)
4. Purge le page cache (`sync && echo 3 > /proc/sys/vm/drop_caches`) — **remplace le reboot**
5. Vérifie que la mitigation est effective (4 contrôles)

Mode cluster en bonus : se copie en SCP sur chaque node listé, s'exécute, se nettoie.

## Installation

```bash
git clone https://github.com/<votre-org>/dirtyfrag-mitigate.git
cd dirtyfrag-mitigate
chmod +x dirtyfrag-mitigate.sh
```

Aucune dépendance hors coreutils + `kmod` (`lsmod`, `modprobe`, `rmmod`) déjà présents sur tout système Linux standard.

## Usage

```bash
# Statut courant — n'écrit rien
bash <(curl -fsSL https://raw.githubusercontent.com/YorkHost-fr/dirtyfrag-mitigation/main/dirtyfrag-mitigation.sh) --check

# Application locale (avec garde-fou IPSec)
bash <(curl -fsSL https://raw.githubusercontent.com/YorkHost-fr/dirtyfrag-mitigation/main/dirtyfrag-mitigation.sh)

# Déploiement sur un cluster Proxmox
./dirtyfrag-mitigate.sh --cluster "pve1 pve2 pve3 pve4 pve5 pve6"

# Bypass du check IPSec (à n'utiliser qu'en dernier recours)
bash <(curl -fsSL https://raw.githubusercontent.com/YorkHost-fr/dirtyfrag-mitigation/main/dirtyfrag-mitigation.sh) --force

# Rollback (uniquement APRÈS installation du kernel patché)
sudo ./dirtyfrag-mitigate.sh --rollback

# Aide
./dirtyfrag-mitigate.sh --help
```

### Codes de sortie

| Code | Signification |
|------|---------------|
| `0` | OK |
| `1` | Erreur générique (argument inconnu, etc.) |
| `2` | Pas root |
| `3` | IPSec actif détecté — mitigation refusée |
| `4` | Vérification post-mitigation échouée |

Pratique pour intégrer dans un Ansible / cron / pipeline.

## Avertissement

⚠️ **Ce script désactive `esp4`, `esp6` et `rxrpc`. Conséquences :**

- **IPSec ESP cassé** : tunnels VPN site-to-site, IKE/strongSwan, etc. ne fonctionnent plus.
- **AFS / kAFS cassé** : très peu d'environnements concernés (rxrpc).
- **Pas d'impact** sur web, SSH, base de données, jeux, virtualisation KVM/LXC standard.

Vérifier `ip xfrm state list` avant application sur un node sensible.

## Désinstallation propre

Une fois que votre distro a publié un kernel patché (à surveiller : [tracker Debian](https://security-tracker.debian.org/tracker/source-package/linux), advisories Proxmox) :

```bash
# 1) Mettre à jour le kernel
apt update && apt upgrade

# 2) Reboot pour repartir sur le kernel patché
reboot

# 3) Retirer la mitigation
sudo ./dirtyfrag-mitigate.sh --rollback
```

## Workaround recommandé par le chercheur

Le script reproduit le workaround officiel publié sur le [repo upstream](https://github.com/V4bel/dirtyfrag), en y ajoutant : la persistance, le drop cache, le check IPSec, le déploiement cluster, et la vérification automatique.

## Références

- [V4bel/dirtyfrag](https://github.com/V4bel/dirtyfrag) — repo officiel + write-up
- [copy.fail](https://copy.fail/) — vulnérabilité de la même classe (CVE-2026-31431)
- [Dirty Pipe](https://dirtypipe.cm4all.com/) — l'ancêtre de cette classe (CVE-2022-0847)

## Licence

[MIT](LICENSE)

## Auteur

Maintenu par [YorkHost](https://yorkhost.fr).
Contributions bienvenues via PR.

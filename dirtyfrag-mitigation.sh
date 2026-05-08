#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  dirtyfrag-mitigate.sh
#  Mitigation Dirty Frag (LPE Linux 0-day, 2026-05-07) sur hosts Proxmox VE.
#  Sans reboot — utilise drop_caches pour purger les pages potentiellement
#  corrompues en RAM.
#
#  Usage :
#    ./dirtyfrag-mitigate.sh                # apply local
#    ./dirtyfrag-mitigate.sh --check        # status seulement, aucune écriture
#    ./dirtyfrag-mitigate.sh --rollback     # retire la mitigation
#    ./dirtyfrag-mitigate.sh --force        # ignore le check IPSec (DANGER)
#    ./dirtyfrag-mitigate.sh --cluster "pve1 pve2 pve3 pve4 pve5 pve6"
#                                           # se copie + s'exécute via SSH
#
#  Exit codes :
#    0  OK
#    1  erreur générique
#    2  pas root
#    3  IPSec actif → mitigation refusée (utiliser --force pour bypass)
#    4  vérification post-mitigation échouée
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

readonly SCRIPT_NAME="${0##*/}"
SCRIPT_PATH="$(readlink -f "$0")"
readonly SCRIPT_PATH
readonly CONF_FILE="/etc/modprobe.d/dirtyfrag.conf"
readonly MODULES=(rxrpc esp4 esp6)   # ordre de déchargement (rxrpc d'abord)

# ── Couleurs ─────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    readonly C_RED=$'\e[31m'
    readonly C_GRN=$'\e[32m'
    readonly C_YLW=$'\e[33m'
    readonly C_BLU=$'\e[34m'
    readonly C_BLD=$'\e[1m'
    readonly C_RST=$'\e[0m'
else
    readonly C_RED='' C_GRN='' C_YLW='' C_BLU='' C_BLD='' C_RST=''
fi

log()    { printf '%s[%s]%s %s\n' "$C_BLU"  "INFO" "$C_RST" "$*"; }
ok()     { printf '%s[%s]%s %s\n' "$C_GRN"  " OK " "$C_RST" "$*"; }
warn()   { printf '%s[%s]%s %s\n' "$C_YLW"  "WARN" "$C_RST" "$*" >&2; }
err()    { printf '%s[%s]%s %s\n' "$C_RED"  "FAIL" "$C_RST" "$*" >&2; }
hr()     { printf '%s%s%s\n' "$C_BLD" "────────────────────────────────────────────────────────────" "$C_RST"; }
title()  { hr; printf '%s%s%s\n' "$C_BLD" "$*" "$C_RST"; hr; }

# ── Pré-conditions ───────────────────────────────────────────────────────────
require_root() {
    if [[ $EUID -ne 0 ]]; then
        err "Doit être lancé en root."
        exit 2
    fi
}

# ── Détection IPSec actif ────────────────────────────────────────────────────
ipsec_is_active() {
    # Renvoie 0 si IPSec actif, 1 sinon.
    local sa pol
    sa=$(ip xfrm state list 2>/dev/null | head -1 || true)
    pol=$(ip xfrm policy list 2>/dev/null | grep -v '^src 0.0.0.0/0 dst 0.0.0.0/0' | head -1 || true)
    [[ -n "$sa" || -n "$pol" ]]
}

# ── Status courant ───────────────────────────────────────────────────────────
print_status() {
    title "État actuel — $(hostname -s)"

    log "Modules kernel chargés (esp4/esp6/rxrpc) :"
    local loaded
    loaded=$(lsmod | awk '/^(esp4|esp6|rxrpc)\s/ {print "  "$1" (refcount="$3")"}')
    if [[ -z "$loaded" ]]; then
        ok "  aucun module vulnérable chargé"
    else
        echo "$loaded"
    fi
    echo

    log "Fichier de blacklist :"
    if [[ -f "$CONF_FILE" ]]; then
        ok "  $CONF_FILE présent"
        sed 's/^/    /' "$CONF_FILE"
    else
        warn "  $CONF_FILE absent (mitigation pas en place)"
    fi
    echo

    log "Résolution modprobe (ce qui se passerait si on tentait de charger) :"
    for m in "${MODULES[@]}"; do
        printf "  %-8s → %s\n" "$m" "$(modprobe -n -v "$m" 2>&1 | tr -s ' ')"
    done
    echo

    log "IPSec actif :"
    if ipsec_is_active; then
        warn "  OUI — au moins une SA ou policy xfrm détectée"
        warn "  ⇒ bloquer esp4/esp6 cassera les tunnels"
    else
        ok "  Non — pas de SA/policy xfrm active"
    fi
}

# ── Application ──────────────────────────────────────────────────────────────
apply_mitigation() {
    local force="${1:-0}"

    title "Application de la mitigation — $(hostname -s)"

    # 1) Garde-fou IPSec
    if ipsec_is_active; then
        if [[ "$force" -eq 1 ]]; then
            warn "IPSec actif détecté — mais --force passé, on continue."
        else
            err "IPSec actif détecté (SA ou policy xfrm présente)."
            err "Bloquer esp4/esp6 cassera les tunnels existants."
            err "Lancer ./$SCRIPT_NAME --check pour voir, ou --force pour bypass."
            exit 3
        fi
    else
        ok "Pas d'IPSec actif — safe to proceed."
    fi

    # 2) Persistance : écrire /etc/modprobe.d/dirtyfrag.conf
    log "Écriture de $CONF_FILE …"
    cat > "$CONF_FILE" <<'EOF'
# Mitigation Dirty Frag (LPE 0-day, 2026-05-07) — V4bel/dirtyfrag
# À retirer une fois le kernel patché disponible (pve-kernel backport).
install esp4 /bin/false
install esp6 /bin/false
install rxrpc /bin/false
EOF
    chmod 644 "$CONF_FILE"
    ok "$CONF_FILE écrit ($(wc -l < "$CONF_FILE") lignes)"

    # 3) Décharger les modules vivants
    log "Déchargement des modules en mémoire…"
    local m unload_failed=0
    for m in "${MODULES[@]}"; do
        if lsmod | awk '{print $1}' | grep -qx "$m"; then
            if modprobe -r "$m" 2>/dev/null || rmmod "$m" 2>/dev/null; then
                ok "  $m déchargé"
            else
                warn "  $m n'a pas pu être déchargé (probablement en cours d'utilisation)"
                unload_failed=1
            fi
        else
            log "  $m pas chargé, skip"
        fi
    done

    if [[ $unload_failed -eq 1 ]]; then
        warn "Au moins un module est resté chargé. Les containers existants peuvent encore"
        warn "déclencher la vuln tant que le module n'est pas dégagé. Reboot recommandé"
        warn "à la prochaine fenêtre de maintenance."
    fi

    # 4) Drop page cache (remplace le reboot)
    log "Drop du page cache (sync + drop_caches=3)…"
    sync
    echo 3 > /proc/sys/vm/drop_caches
    ok "Page cache purgé"

    echo
    ok "Mitigation appliquée."
}

# ── Vérification post-mitigation ─────────────────────────────────────────────
verify_mitigation() {
    title "Vérification post-mitigation — $(hostname -s)"

    local errors=0

    # 1) Aucun module chargé
    if lsmod | awk '/^(esp4|esp6|rxrpc)\s/' | grep -q .; then
        err "Module(s) encore chargé(s) :"
        lsmod | awk '/^(esp4|esp6|rxrpc)\s/ {print "    "$1}' >&2
        ((errors++))
    else
        ok "1/4  Aucun module vulnérable chargé"
    fi

    # 2) Le fichier de blacklist existe
    if [[ -f "$CONF_FILE" ]]; then
        ok "2/4  $CONF_FILE en place"
    else
        err "$CONF_FILE manquant"
        ((errors++))
    fi

    # 3) modprobe résout bien vers /bin/false
    local m mp_out fail3=0
    for m in "${MODULES[@]}"; do
        mp_out=$(modprobe -n -v "$m" 2>&1)
        if [[ "$mp_out" == *"/bin/false"* ]]; then
            :
        else
            err "  modprobe -n -v $m → $mp_out (attendu: install /bin/false)"
            fail3=1
        fi
    done
    if [[ $fail3 -eq 0 ]]; then
        ok "3/4  modprobe pointe bien vers /bin/false pour les 3 modules"
    else
        ((errors++))
    fi

    # 4) Tentative de chargement explicite — doit échouer
    local m4 fail4=0
    for m4 in "${MODULES[@]}"; do
        if modprobe "$m4" 2>/dev/null; then
            err "  modprobe $m4 a réussi (ne devrait pas !)"
            fail4=1
        fi
    done
    if [[ $fail4 -eq 0 ]]; then
        ok "4/4  Chargement explicite des 3 modules : refusé (OK)"
    else
        ((errors++))
    fi

    echo
    if [[ $errors -eq 0 ]]; then
        ok "${C_BLD}Toutes les vérifications sont passées.${C_RST}"
        return 0
    else
        err "${C_BLD}$errors vérification(s) échouée(s).${C_RST}"
        return 4
    fi
}

# ── Rollback ─────────────────────────────────────────────────────────────────
rollback() {
    title "Rollback — $(hostname -s)"
    warn "Le rollback n'a de sens QUE si le kernel patché est déjà installé."
    warn "Sinon, le host redevient vulnérable."

    if [[ -f "$CONF_FILE" ]]; then
        rm -f "$CONF_FILE"
        ok "Supprimé : $CONF_FILE"
    else
        log "$CONF_FILE déjà absent."
    fi

    log "Reboot recommandé pour repartir sur un kernel propre."
    log "Sinon, recharger manuellement : modprobe esp4 esp6 (selon besoin)."
}

# ── Mode cluster (SSH loop) ──────────────────────────────────────────────────
cluster_mode() {
    local nodes_str="$1"
    shift  # le reste = arguments à passer au script distant
    local extra_args=("$@")

    title "Déploiement cluster"
    log "Nodes cibles : $nodes_str"
    log "Args distants : ${extra_args[*]:-<aucun>}"
    echo

    local node global_rc=0
    for node in $nodes_str; do
        printf '\n%s═══ %s ═══%s\n' "$C_BLD" "$node" "$C_RST"

        # Push le script
        if ! scp -q -o StrictHostKeyChecking=accept-new \
                "$SCRIPT_PATH" "root@$node:/tmp/$SCRIPT_NAME"; then
            err "[$node] scp échoué"
            global_rc=1
            continue
        fi

        # Exécution distante
        if ssh -o StrictHostKeyChecking=accept-new "root@$node" \
              "chmod +x /tmp/$SCRIPT_NAME && /tmp/$SCRIPT_NAME ${extra_args[*]:-} && rm -f /tmp/$SCRIPT_NAME"; then
            ok "[$node] terminé OK"
        else
            local rc=$?
            err "[$node] terminé avec exit code $rc"
            global_rc=1
        fi
    done

    echo
    if [[ $global_rc -eq 0 ]]; then
        ok "Cluster : tous les nodes OK."
    else
        err "Cluster : au moins un node a échoué (voir log au-dessus)."
    fi
    return $global_rc
}

# ── Usage ────────────────────────────────────────────────────────────────────
usage() {
    cat <<EOF
$SCRIPT_NAME — mitigation Dirty Frag pour Proxmox VE

USAGE :
    $SCRIPT_NAME                     Applique la mitigation localement
    $SCRIPT_NAME --check             Affiche le statut, n'écrit rien
    $SCRIPT_NAME --rollback          Retire la mitigation (après patch !)
    $SCRIPT_NAME --force             Ignore le check IPSec (DANGER)
    $SCRIPT_NAME --cluster "n1 n2"   Déploie via SSH sur les nodes listés
    $SCRIPT_NAME --help              Affiche ce message

EXEMPLES :
    # Vérifier sans rien casser
    sudo $SCRIPT_NAME --check

    # Appliquer sur le node courant
    sudo $SCRIPT_NAME

    # Déployer sur tout le cluster
    $SCRIPT_NAME --cluster "pve1 pve2 pve3 pve4 pve5 pve6"

    # Déployer + bypass IPSec (cas extrême, à éviter)
    $SCRIPT_NAME --cluster "pve1 pve2" --force
EOF
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
    local mode="apply"
    local force=0
    local cluster_nodes=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --check)    mode="check"; shift ;;
            --rollback) mode="rollback"; shift ;;
            --force)    force=1; shift ;;
            --cluster)
                mode="cluster"
                cluster_nodes="${2:-}"
                if [[ -z "$cluster_nodes" ]]; then
                    err "--cluster requiert une liste de nodes entre guillemets"
                    exit 1
                fi
                shift 2
                ;;
            -h|--help)  usage; exit 0 ;;
            *)
                err "Argument inconnu : $1"
                usage
                exit 1
                ;;
        esac
    done

    case "$mode" in
        check)
            require_root
            print_status
            ;;
        apply)
            require_root
            print_status
            echo
            apply_mitigation "$force"
            echo
            verify_mitigation
            ;;
        rollback)
            require_root
            rollback
            ;;
        cluster)
            local extra=()
            [[ $force -eq 1 ]] && extra+=("--force")
            cluster_mode "$cluster_nodes" "${extra[@]}"
            ;;
    esac
}

main "$@"

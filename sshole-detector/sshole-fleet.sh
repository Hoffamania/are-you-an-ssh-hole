#!/bin/sh
# sshole-fleet.sh — run sshole-audit.sh across hosts you already administer.
#
# For each host it opens an SSH session WITH YOUR OWN CREDENTIALS (key-based;
# BatchMode is forced on, so it can never fall back to sending a password),
# pipes the local audit script in over stdin, runs it there, and collects the
# verdict. It performs no password probing and no authentication bypass against
# anything — it only orchestrates the safe local detector over access you hold.
#
# Usage:
#   ./sshole-fleet.sh host1 host2 user@host3
#   ./sshole-fleet.sh --hosts hosts.txt
#   ./sshole-fleet.sh --sudo --jobs 20 --hosts hosts.txt --out results/
#
# Options:
#   --hosts FILE   read hosts from FILE (one per line; # comments and blanks ok)
#   --sudo         run the remote audit under `sudo -n` (needs passwordless sudo)
#   --jobs N       run up to N hosts concurrently (default 10)
#   --user U       ssh login user for hosts given without user@
#   --identity K   ssh identity file
#   --timeout S    ssh connect timeout seconds (default 10)
#   --out DIR      save each host's full audit output to DIR/<host>.txt
#
# Exit: 0 all clear · 1 at least one VULNERABLE · 2 some NEEDS_REVIEW/UNREACHABLE/ERROR
#
# Source with SSHOLE_LIB=1 to load functions without running main (for tests).

set -u

# ----- pure helpers (unit-tested) --------------------------------------------

# Map an ssh/audit exit code to a status token.
classify_rc() {
    case "$1" in
        0)   echo NOT_VULNERABLE ;;
        1)   echo VULNERABLE ;;
        2)   echo NEEDS_REVIEW ;;
        255) echo UNREACHABLE ;;
        *)   echo ERROR ;;
    esac
}

# Read host lines from stdin: strip "#" comments, trim, drop blanks.
read_hosts() {
    sed 's/#.*//' | while IFS= read -r line; do
        h=$(printf '%s' "$line" | tr -d '[:space:]')
        [ -n "$h" ] && echo "$h"
    done
}

# ----- main ------------------------------------------------------------------

main() {
    here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
    AUDIT="$here/sshole-audit.sh"
    [ -r "$AUDIT" ] || { echo "cannot find sshole-audit.sh next to this script" >&2; exit 3; }

    HOSTS=""; SUDO=""; JOBS=10; SSH_USER=""; IDENTITY=""; TIMEOUT=10; OUTDIR=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --hosts)    HOSTS="$HOSTS $(read_hosts < "$2")"; shift 2 ;;
            --sudo)     SUDO="sudo -n "; shift ;;
            --jobs)     JOBS="$2"; shift 2 ;;
            --user)     SSH_USER="$2"; shift 2 ;;
            --identity) IDENTITY="$2"; shift 2 ;;
            --timeout)  TIMEOUT="$2"; shift 2 ;;
            --out)      OUTDIR="$2"; mkdir -p "$OUTDIR"; shift 2 ;;
            --help|-h)  sed -n '2,30p' "$0"; exit 0 ;;
            -*)         echo "unknown option: $1" >&2; exit 3 ;;
            *)          HOSTS="$HOSTS $1"; shift ;;
        esac
    done

    HOSTS=$(printf '%s\n' $HOSTS | awk 'NF && !seen[$0]++')
    [ -n "$HOSTS" ] || { echo "no hosts given (use positional args or --hosts FILE)" >&2; exit 3; }

    SSH_OPTS="-o BatchMode=yes -o ConnectTimeout=$TIMEOUT"
    [ -n "$SSH_USER" ] && SSH_OPTS="$SSH_OPTS -l $SSH_USER"
    [ -n "$IDENTITY" ] && SSH_OPTS="$SSH_OPTS -i $IDENTITY"
    REMOTE_CMD="${SUDO}sh -s"

    RESDIR=$(mktemp -d)
    trap 'rm -rf "$RESDIR"' EXIT INT TERM

    idx=0; running=0
    for host in $HOSTS; do
        idx=$((idx+1))
        (
            out=$(ssh $SSH_OPTS "$host" "$REMOTE_CMD" < "$AUDIT" 2>&1)
            rc=$?
            printf '%s\t%s\n' "$host" "$(classify_rc "$rc")" > "$RESDIR/$idx.res"
            [ -n "$OUTDIR" ] && printf '%s\n' "$out" > "$OUTDIR/$(echo "$host" | tr -c 'A-Za-z0-9._-' '_').txt"
        ) &
        running=$((running+1))
        [ "$running" -ge "$JOBS" ] && { wait; running=0; }
    done
    wait

    vuln=0; review=0; clear=0; bad=0
    echo "sshole fleet audit"
    echo "-------------------------------------------------"
    for f in "$RESDIR"/*.res; do
        [ -e "$f" ] || continue
        host=$(cut -f1 "$f"); status=$(cut -f2 "$f")
        printf '  %-36s %s\n' "$host" "$status"
        case "$status" in
            VULNERABLE)     vuln=$((vuln+1)) ;;
            NEEDS_REVIEW)   review=$((review+1)) ;;
            NOT_VULNERABLE) clear=$((clear+1)) ;;
            *)              bad=$((bad+1)) ;;
        esac
    done
    echo "-------------------------------------------------"
    echo "  vulnerable: $vuln   needs-review: $review   clear: $clear   unreachable/error: $bad"

    [ "$vuln" -gt 0 ] && exit 1
    { [ "$review" -gt 0 ] || [ "$bad" -gt 0 ]; } && exit 2
    exit 0
}

if [ "${SSHOLE_LIB:-}" != "1" ]; then
    main "$@"
fi

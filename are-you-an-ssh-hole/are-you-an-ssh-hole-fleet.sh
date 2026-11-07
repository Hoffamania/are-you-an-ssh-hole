#!/bin/sh
# are-you-an-ssh-hole-fleet.sh — run are-you-an-ssh-hole.sh across hosts you already administer.
#
# For each host it opens an SSH session WITH YOUR OWN CREDENTIALS (key-based;
# BatchMode is forced on, so it can never fall back to sending a password),
# pipes the local audit script in over stdin, runs it there, and collects the
# verdict. It performs no password probing and no authentication bypass against
# anything — it only orchestrates the safe local detector over access you hold.
#
# Usage:
#   ./are-you-an-ssh-hole-fleet.sh host1 host2 user@host3
#   ./are-you-an-ssh-hole-fleet.sh --hosts hosts.txt
#   ./are-you-an-ssh-hole-fleet.sh --sudo --jobs 20 --hosts hosts.txt --out results/
#
# Options:
#   --hosts FILE   read hosts from FILE (one per line; # comments and blanks ok)
#   --sudo         run the remote audit under `sudo -n` (needs passwordless sudo)
#   --jobs N       run up to N hosts concurrently (default 10)
#   --user U       ssh login user for hosts given without user@
#   --identity K   ssh identity file
#   --timeout S    ssh connect timeout seconds (default 10)
#   --out DIR      save each host's full audit output to DIR/<host>.{txt,json}
#   --json         emit one aggregated JSON report (summary + per-host records)
#                  instead of the human-readable table
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

# Decide the overall exit code from the verdict counts.
# Args: vuln review bad  ->  1 (any vuln) | 2 (any review/unreachable) | 0
fleet_exit_code() {
    if [ "$1" -gt 0 ]; then echo 1
    elif [ "$2" -gt 0 ] || [ "$3" -gt 0 ]; then echo 2
    else echo 0; fi
}

# Escape a string for a JSON double-quoted value.
json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\r' | tr '\n\t' '  '
}

# ----- main ------------------------------------------------------------------

main() {
    here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
    AUDIT="$here/are-you-an-ssh-hole.sh"
    [ -r "$AUDIT" ] || { echo "cannot find are-you-an-ssh-hole.sh next to this script" >&2; exit 3; }

    HOSTS=""; SUDO=""; JOBS=10; SSH_USER=""; IDENTITY=""; TIMEOUT=10; OUTDIR=""; FMT=text
    while [ $# -gt 0 ]; do
        case "$1" in
            --hosts)    HOSTS="$HOSTS $(read_hosts < "$2")"; shift 2 ;;
            --json)     FMT=json; shift ;;
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
    if [ "$FMT" = json ]; then REMOTE_CMD="${SUDO}sh -s -- --json"; OUTEXT=json
    else REMOTE_CMD="${SUDO}sh -s"; OUTEXT=txt; fi

    RESDIR=$(mktemp -d)
    trap 'rm -rf "$RESDIR"' EXIT INT TERM

    idx=0; running=0
    for host in $HOSTS; do
        idx=$((idx+1))
        (
            if [ "$FMT" = json ]; then
                out=$(ssh $SSH_OPTS "$host" "$REMOTE_CMD" < "$AUDIT" 2>/dev/null)
            else
                out=$(ssh $SSH_OPTS "$host" "$REMOTE_CMD" < "$AUDIT" 2>&1)
            fi
            rc=$?
            status=$(classify_rc "$rc")
            printf '%s\t%s\n' "$host" "$status" > "$RESDIR/$idx.res"
            if [ "$FMT" = json ]; then
                if printf '%s' "$out" | head -1 | grep -q '^{'; then
                    printf '%s' "$out" > "$RESDIR/$idx.json"
                else
                    printf '{"host":"%s","verdict":"%s","evidence":null}' \
                        "$(json_escape "$host")" "$status" > "$RESDIR/$idx.json"
                fi
            fi
            [ -n "$OUTDIR" ] && printf '%s\n' "$out" > "$OUTDIR/$(echo "$host" | tr -c 'A-Za-z0-9._-' '_').$OUTEXT"
        ) &
        running=$((running+1))
        [ "$running" -ge "$JOBS" ] && { wait; running=0; }
    done
    wait

    vuln=0; review=0; clear=0; bad=0
    for f in "$RESDIR"/*.res; do
        [ -e "$f" ] || continue
        case "$(cut -f2 "$f")" in
            VULNERABLE)     vuln=$((vuln+1)) ;;
            NEEDS_REVIEW)   review=$((review+1)) ;;
            NOT_VULNERABLE) clear=$((clear+1)) ;;
            *)              bad=$((bad+1)) ;;
        esac
    done
    total=$((vuln+review+clear+bad))

    if [ "$FMT" = json ]; then
        printf '{\n'
        printf '  "schema": "are-you-an-ssh-hole-fleet/v1",\n'
        printf '  "generated_at": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"
        printf '  "summary": {"total": %s, "vulnerable": %s, "needs_review": %s, "not_vulnerable": %s, "unreachable_or_error": %s},\n' \
            "$total" "$vuln" "$review" "$clear" "$bad"
        printf '  "hosts": [\n'
        first=1
        for f in "$RESDIR"/*.json; do
            [ -e "$f" ] || continue
            [ "$first" = 1 ] || printf ',\n'
            first=0
            sed 's/^/    /' "$f"
        done
        printf '\n  ]\n}\n'
    else
        echo "sshole fleet audit"
        echo "-------------------------------------------------"
        for f in "$RESDIR"/*.res; do
            [ -e "$f" ] || continue
            printf '  %-36s %s\n' "$(cut -f1 "$f")" "$(cut -f2 "$f")"
        done
        echo "-------------------------------------------------"
        echo "  vulnerable: $vuln   needs-review: $review   clear: $clear   unreachable/error: $bad"
    fi

    exit "$(fleet_exit_code "$vuln" "$review" "$bad")"
}

if [ "${SSHOLE_LIB:-}" != "1" ]; then
    main "$@"
fi

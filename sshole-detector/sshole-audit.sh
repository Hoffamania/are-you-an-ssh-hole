#!/bin/sh
# sshole-audit.sh — local detector for the musl/OpenSSH "*"-password auth bypass.
#
# Runs ON a host and reports whether THAT host is in the vulnerable configuration.
# It reads local config and reproduces the crypt() defect in isolation. It makes
# no network connections and attempts no authentication against anything.
#
# Exit codes:
#   0  NOT_VULNERABLE   conditions for the bypass are not present
#   1  VULNERABLE       all conditions confirmed
#   2  NEEDS_REVIEW     some signal present but a condition could not be determined
#
# Source it with SSHOLE_LIB=1 to load the functions without running main (for tests).

set -u

# ----- fact collectors -------------------------------------------------------

# Prints: musl | glibc | unknown
detect_libc() {
    if [ -n "$(ls /lib/ld-musl-*.so.1 2>/dev/null)" ]; then
        echo musl; return
    fi
    ver=$(ldd --version 2>&1 | head -1)
    case "$ver" in
        *musl*)  echo musl ;;
        *GLIBC*|*GNU*|*glibc*) echo glibc ;;
        *) echo unknown ;;
    esac
}

# Prints the sshd version string, or empty if sshd not found.
get_sshd_version() {
    if command -v sshd >/dev/null 2>&1; then
        sshd -V 2>&1 | head -1 || true
    else
        echo ""
    fi
}

# Prints usernames whose /etc/shadow password field is exactly "*".
# Reads from $1 if given (used by tests); otherwise /etc/shadow.
scan_star_accounts() {
    f="${1:-/etc/shadow}"
    [ -r "$f" ] || { echo "__UNREADABLE__"; return; }
    while IFS=: read -r user field rest; do
        [ "$field" = "*" ] && echo "$user"
    done < "$f"
}

# Prints the number of accounts with a SHA-256 ($5$) or SHA-512 ($6$) hash.
# These supply the "donor" salt sshd borrows for a "*" account, so at least one
# must exist for the bypass to trigger (Orca disclosure). Reads $1 or /etc/shadow.
scan_sha_accounts() {
    f="${1:-/etc/shadow}"
    [ -r "$f" ] || { echo "__UNREADABLE__"; return; }
    n=0
    while IFS=: read -r user field rest; do
        case "$field" in
            '$5$'*|'$6$'*) n=$((n+1)) ;;
        esac
    done < "$f"
    echo "$n"
}

# Reproduce the defect in isolation: does crypt(<password over 256 bytes>, "*")
# return "*"? That return value is exactly what makes a "*" account match.
# Prints: yes | no | unknown
crypt_returns_star() {
    long=$(printf 'A%.0s' $(seq 1 300))
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$long" <<'PY' 2>/dev/null && return
import sys
try:
    import crypt
except Exception:
    sys.exit(42)
r = crypt.crypt(sys.argv[1], "*")
print("yes" if r == "*" else "no")
PY
    fi
    if command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1; then
        CC=$(command -v cc || command -v gcc)
        tmp=$(mktemp -d)
        cat > "$tmp/p.c" <<'C'
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#if __has_include(<crypt.h>)
#include <crypt.h>
#else
#include <unistd.h>
#endif
int main(void){
    char pw[301];
    memset(pw,'A',300); pw[300]='\0';      /* > 256 bytes */
    char *r = crypt(pw, "*");               /* salt is the locked-account field */
    if(!r){ printf("no\n"); return 0; }     /* NULL cannot match "*" */
    printf("%s\n", strcmp(r,"*")==0 ? "yes" : "no");
    return 0;
}
C
        if "$CC" -o "$tmp/p" "$tmp/p.c" >/dev/null 2>&1 || "$CC" -o "$tmp/p" "$tmp/p.c" -lcrypt >/dev/null 2>&1; then
            out=$("$tmp/p" 2>/dev/null)
            rm -rf "$tmp"
            case "$out" in yes) echo yes;; no) echo no;; *) echo unknown;; esac
            return
        fi
        rm -rf "$tmp"
    fi
    echo unknown
}

# Does the sshd PAM path likely shield "*" accounts from crypt()?
# Prints: shielded | not_shielded | unknown
detect_pam_shield() {
    cfg="${1:-/etc/ssh/sshd_config}"
    pam="${2:-/etc/pam.d/sshd}"
    [ -r "$cfg" ] || { echo unknown; return; }
    usepam=$(grep -iE '^[[:space:]]*UsePAM[[:space:]]+yes' "$cfg" 2>/dev/null)
    if [ -n "$usepam" ] && [ -r "$pam" ]; then
        echo shielded
    elif [ -n "$usepam" ]; then
        echo unknown
    else
        echo not_shielded
    fi
}

# Is the OpenSSH fix applied? The fix is in OpenSSH, not musl, so a patched host
# still has musl returning "*". On Alpine, fixes are backported, so compare the
# installed apk version against the per-branch fixed version with apk's own
# comparator. Elsewhere, compare the upstream version against 10.6p2.
# Prints: patched | unpatched | unknown
openssh_fix_status() {
    if [ -f /etc/alpine-release ] && command -v apk >/dev/null 2>&1; then
        rel=$(cat /etc/alpine-release 2>/dev/null)
        branch=$(echo "$rel" | grep -oE '^[0-9]+\.[0-9]+' | head -1)
        inst=$(apk list -I openssh 2>/dev/null | grep -oE 'openssh-[^ ]+' | head -1 | sed 's/^openssh-//')
        [ -z "$inst" ] && { echo unknown; return; }
        case "$branch" in
            3.24) fixed=10.3_p1-r2 ;;
            3.23) fixed=10.2_p1-r1 ;;
            3.22) fixed=10.0_p1-r11 ;;
            3.21) fixed=9.9_p2-r1 ;;
            3.20) fixed=9.7_p1-r6 ;;
            *)    if echo "$rel" | grep -qi edge; then fixed=10.6_p2-r0
                  else echo unknown; return; fi ;;
        esac
        case "$(apk version -t "$inst" "$fixed" 2>/dev/null)" in
            '<')     echo unpatched ;;
            '='|'>') echo patched ;;
            *)       echo unknown ;;
        esac
        return
    fi
    # Non-Alpine musl: compare upstream OpenSSH version against 10.6p2.
    v=$(get_sshd_version | grep -oiE 'OpenSSH_[0-9]+\.[0-9]+(p[0-9]+)?' | head -1 | sed 's/OpenSSH_//I')
    [ -z "$v" ] && { echo unknown; return; }
    maj=$(echo "$v" | cut -d. -f1)
    min=$(echo "$v" | sed -E 's/^[0-9]+\.([0-9]+).*/\1/')
    p=$(echo "$v" | grep -oE 'p[0-9]+' | tr -d p); p=${p:-0}
    { [ "$maj" -gt 10 ]; } 2>/dev/null && { echo patched; return; }
    { [ "$maj" -lt 10 ]; } 2>/dev/null && { echo unpatched; return; }
    { [ "$min" -gt 6 ]; } 2>/dev/null && { echo patched; return; }
    { [ "$min" -lt 6 ]; } 2>/dev/null && { echo unpatched; return; }
    { [ "$p" -ge 2 ]; } 2>/dev/null && echo patched || echo unpatched
}

# ----- verdict (pure function of the facts; unit-tested) ---------------------
# Args: libc  crypt_star(yes|no|unknown)  star_accounts(count|__UNREADABLE__)
#       sha_accounts(count|__UNREADABLE__)  sshd_present(yes|no)
#       pam(shielded|not_shielded|unknown)  fix(patched|unpatched|unknown)
# Prints RESULT token on stdout; sets no globals.
compute_verdict() {
    _libc="$1"; _crypt="$2"; _star="$3"; _sha="$4"; _sshd="$5"; _pam="$6"; _fix="$7"

    # Definitively safe: the core crypt "*" defect is absent.
    if [ "$_crypt" = "no" ] || [ "$_libc" = "glibc" ]; then
        echo NOT_VULNERABLE; return
    fi
    # Core defect could not be determined (libc not identified, or probe failed).
    if [ "$_libc" != "musl" ] || [ "$_crypt" = "unknown" ]; then
        echo NEEDS_REVIEW; return
    fi
    # musl + crypt returns "*". The OpenSSH patch is authoritative.
    if [ "$_fix" = "patched" ]; then
        echo NOT_VULNERABLE; return
    fi
    if [ "$_sshd" = "no" ]; then
        echo NOT_VULNERABLE; return
    fi
    if [ "$_star" = "__UNREADABLE__" ] || [ "$_sha" = "__UNREADABLE__" ]; then
        echo NEEDS_REVIEW; return
    fi
    # Both a "*" account and a SHA-256/512 donor account are required.
    if [ "$_star" = "0" ] || [ "$_sha" = "0" ]; then
        echo NOT_VULNERABLE; return
    fi
    # PAM detection is heuristic, so flag rather than clear.
    if [ "$_pam" = "shielded" ]; then
        echo NEEDS_REVIEW; return
    fi
    # All conditions hold; verdict hinges on whether the patch is confirmed.
    if [ "$_fix" = "unpatched" ]; then
        echo VULNERABLE
    else
        echo NEEDS_REVIEW
    fi
}

# ----- main ------------------------------------------------------------------

main() {
    if [ "${1:-}" = "--crypt-probe" ]; then
        echo "crypt(<300 bytes>, \"*\") returns \"*\": $(crypt_returns_star)"
        exit 0
    fi

    libc=$(detect_libc)
    sshver=$(get_sshd_version)
    [ -n "$sshver" ] && sshd_present=yes || sshd_present=no
    crypt_star=$(crypt_returns_star)
    star_raw=$(scan_star_accounts)
    sha_count=$(scan_sha_accounts)
    pam=$(detect_pam_shield)
    fix=$(openssh_fix_status)

    if [ "$star_raw" = "__UNREADABLE__" ]; then
        star_count=__UNREADABLE__
        star_note="/etc/shadow not readable (run as root for a definitive result)"
    else
        star_count=$(printf '%s\n' "$star_raw" | grep -c . || true)
        star_note="$star_count account(s) with a '*' password field"
    fi
    if [ "$sha_count" = "__UNREADABLE__" ]; then
        sha_note="(shadow unreadable)"
    else
        sha_note="$sha_count account(s) with a SHA-256/512 hash (donor salt)"
    fi

    result=$(compute_verdict "$libc" "$crypt_star" "$star_count" "$sha_count" "$sshd_present" "$pam" "$fix")

    echo "sshole audit"
    echo "  libc:                $libc"
    echo "  sshd:                ${sshver:-not found}"
    echo "  OpenSSH fix status:  $fix"
    echo "  crypt returns '*':   $crypt_star"
    echo "  '*' accounts:        $star_note"
    [ "$star_count" != "__UNREADABLE__" ] && [ "$star_count" != "0" ] && \
        printf '                       %s\n' $star_raw
    echo "  SHA donor accounts:  $sha_note"
    echo "  PAM path:            $pam"
    echo "  RESULT:              $result"

    case "$result" in
        VULNERABLE)     exit 1 ;;
        NEEDS_REVIEW)   exit 2 ;;
        *)              exit 0 ;;
    esac
}

if [ "${SSHOLE_LIB:-}" != "1" ]; then
    main "$@"
fi

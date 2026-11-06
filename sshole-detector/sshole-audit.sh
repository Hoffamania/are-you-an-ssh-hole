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

# ----- verdict (pure function of the facts; unit-tested) ---------------------
# Args: libc  crypt_star(yes|no|unknown)  star_accounts(count or __UNREADABLE__)
#       sshd_present(yes|no)  pam(shielded|not_shielded|unknown)
# Prints RESULT token on stdout; sets no globals.
compute_verdict() {
    _libc="$1"; _crypt="$2"; _accounts="$3"; _sshd="$4"; _pam="$5"

    # Definitively safe: the core crypt "*" defect is absent.
    if [ "$_crypt" = "no" ] || [ "$_libc" = "glibc" ]; then
        echo NOT_VULNERABLE; return
    fi
    # Core defect could not be determined (libc not identified, or probe failed).
    if [ "$_libc" != "musl" ] || [ "$_crypt" = "unknown" ]; then
        echo NEEDS_REVIEW; return
    fi
    # Here: musl + crypt returns "*".
    if [ "$_accounts" = "__UNREADABLE__" ]; then
        echo NEEDS_REVIEW; return
    fi
    if [ "$_accounts" = "0" ] || [ "$_sshd" = "no" ]; then
        echo NOT_VULNERABLE; return
    fi
    if [ "$_pam" = "shielded" ]; then
        echo NEEDS_REVIEW; return
    fi
    echo VULNERABLE
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
    accounts_raw=$(scan_star_accounts)
    pam=$(detect_pam_shield)

    if [ "$accounts_raw" = "__UNREADABLE__" ]; then
        acct_count=__UNREADABLE__
        acct_note="/etc/shadow not readable (run as root for a definitive result)"
    else
        acct_count=$(printf '%s\n' "$accounts_raw" | grep -c . || true)
        acct_note="$acct_count account(s) with a '*' password field"
    fi

    result=$(compute_verdict "$libc" "$crypt_star" "$acct_count" "$sshd_present" "$pam")

    echo "sshole audit"
    echo "  libc:                $libc"
    echo "  sshd:                ${sshver:-not found}"
    echo "  crypt returns '*':   $crypt_star"
    echo "  '*' accounts:        $acct_note"
    [ "$acct_count" != "__UNREADABLE__" ] && [ "$acct_count" != "0" ] && \
        printf '                       %s\n' $accounts_raw
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

#!/bin/sh
# Unit tests for are-you-an-ssh-hole.sh.
# Loads the script as a library and exercises compute_verdict with fixtures,
# plus the shadow scanner against synthetic /etc/shadow files.
set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SSHOLE_LIB=1 . "$here/../are-you-an-ssh-hole.sh"
SSHOLE_LIB=1 . "$here/../are-you-an-ssh-hole-fleet.sh"

pass=0; fail=0
check() { # desc  expected  actual
    if [ "$2" = "$3" ]; then
        pass=$((pass+1))
    else
        fail=$((fail+1))
        printf 'FAIL: %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}

# compute_verdict  libc crypt_star star_acct sha_acct sshd pam fix
check "all conditions + unpatched = VULNERABLE" \
    VULNERABLE     "$(compute_verdict musl yes 1 1 yes not_shielded unpatched)"
check "all conditions but PATCHED OpenSSH = NOT_VULNERABLE" \
    NOT_VULNERABLE "$(compute_verdict musl yes 1 1 yes not_shielded patched)"
check "all conditions but fix status unknown = NEEDS_REVIEW" \
    NEEDS_REVIEW   "$(compute_verdict musl yes 1 1 yes not_shielded unknown)"
check "glibc is never vulnerable" \
    NOT_VULNERABLE "$(compute_verdict glibc no 1 1 yes not_shielded unpatched)"
check "musl but crypt does not return '*' = NOT_VULNERABLE" \
    NOT_VULNERABLE "$(compute_verdict musl no 1 1 yes not_shielded unpatched)"
check "no '*' accounts = NOT_VULNERABLE" \
    NOT_VULNERABLE "$(compute_verdict musl yes 0 1 yes not_shielded unpatched)"
check "no SHA-256/512 donor account = NOT_VULNERABLE" \
    NOT_VULNERABLE "$(compute_verdict musl yes 1 0 yes not_shielded unpatched)"
check "no sshd = NOT_VULNERABLE" \
    NOT_VULNERABLE "$(compute_verdict musl yes 1 1 no not_shielded unpatched)"
check "PAM shield on an otherwise-vulnerable host = NEEDS_REVIEW" \
    NEEDS_REVIEW   "$(compute_verdict musl yes 1 1 yes shielded unpatched)"
check "shadow unreadable = NEEDS_REVIEW" \
    NEEDS_REVIEW   "$(compute_verdict musl yes __UNREADABLE__ __UNREADABLE__ yes not_shielded unpatched)"
check "unknown libc = NEEDS_REVIEW" \
    NEEDS_REVIEW   "$(compute_verdict unknown unknown 1 1 yes unknown unknown)"

# scan_star_accounts against fixtures
tmp=$(mktemp -d)
cat > "$tmp/shadow_vuln" <<'EOF'
root:*:19000:0:99999:7:::
deploy:*:19000:0:99999:7:::
alice:$6$abc$realhashgoeshere:19000:0:99999:7:::
bob:!:19000:0:99999:7:::
EOF
got=$(scan_star_accounts "$tmp/shadow_vuln" | tr '\n' ',' )
check "scanner finds exactly the '*' accounts" "root,deploy," "$got"

got=$(scan_sha_accounts "$tmp/shadow_vuln")
check "SHA scanner counts \$5\$/\$6\$ donor accounts" "1" "$got"

cat > "$tmp/shadow_safe" <<'EOF'
root:!:19000:0:99999:7:::
alice:$6$abc$hash:19000:0:99999:7:::
svc:*0:19000:0:99999:7:::
EOF
got=$(scan_star_accounts "$tmp/shadow_safe" | tr '\n' ',')
check "'!' and '*0' are not treated as '*'" "" "$got"

got=$(scan_star_accounts "$tmp/does_not_exist")
check "unreadable shadow reports sentinel" "__UNREADABLE__" "$got"

# --- fleet helpers ---
check "rc 0 -> NOT_VULNERABLE" NOT_VULNERABLE "$(classify_rc 0)"
check "rc 1 -> VULNERABLE"     VULNERABLE     "$(classify_rc 1)"
check "rc 2 -> NEEDS_REVIEW"   NEEDS_REVIEW   "$(classify_rc 2)"
check "rc 255 -> UNREACHABLE"  UNREACHABLE    "$(classify_rc 255)"
check "rc 127 -> ERROR"        ERROR          "$(classify_rc 127)"

cat > "$tmp/hosts.txt" <<'EOF'
# fleet hosts
web1.example.com
  user@web2.example.com   # trailing comment

db1.example.com
EOF
got=$(read_hosts < "$tmp/hosts.txt" | tr '\n' ',')
check "host file parse strips comments/blanks/space" \
    "web1.example.com,user@web2.example.com,db1.example.com," "$got"
rm -rf "$tmp"

# --- version_is_patched (fixed point: upstream 10.6p2) ---
check "10.6p2 is patched (boundary)"  patched   "$(version_is_patched 10.6p2)"
check "10.6p1 is unpatched"           unpatched "$(version_is_patched 10.6p1)"
check "10.6 (no p) is unpatched"      unpatched "$(version_is_patched 10.6)"
check "10.7p1 is patched"             patched   "$(version_is_patched 10.7p1)"
check "10.5p9 is unpatched"           unpatched "$(version_is_patched 10.5p9)"
check "11.0 is patched"               patched   "$(version_is_patched 11.0)"
check "9.9p2 is unpatched"            unpatched "$(version_is_patched 9.9p2)"
check "full banner string parses"    patched   "$(version_is_patched 'OpenSSH_10.6p2, OpenSSL 3.0')"
check "non-version string is unknown" unknown   "$(version_is_patched 'not a version')"

# --- fleet_exit_code (vuln > review/unreachable > clear) ---
check "any vulnerable -> exit 1"       1 "$(fleet_exit_code 1 0 0)"
check "vuln dominates review+bad"      1 "$(fleet_exit_code 2 3 1)"
check "review only -> exit 2"          2 "$(fleet_exit_code 0 3 0)"
check "unreachable/error only -> exit 2" 2 "$(fleet_exit_code 0 0 2)"
check "all clear -> exit 0"            0 "$(fleet_exit_code 0 0 0)"

# --- syntax lint: every script must parse ---
for s in "$here/../are-you-an-ssh-hole.sh" "$here/../are-you-an-ssh-hole-fleet.sh" "$here/run-tests.sh"; do
    sh -n "$s" 2>/dev/null
    check "sh -n parses $(basename "$s")" 0 "$?"
done

# --- integration smoke: the audit actually runs and exits cleanly ---
sh "$here/../are-you-an-ssh-hole.sh" --crypt-probe >/dev/null 2>&1
check "--crypt-probe exits 0" 0 "$?"
sh "$here/../are-you-an-ssh-hole.sh" >/dev/null 2>&1; rc=$?
case "$rc" in 0|1|2) ok=yes ;; *) ok=no ;; esac
check "full audit exits with a valid verdict code (0/1/2)" yes "$ok"

echo "-------------------------------------"
echo "passed: $pass   failed: $fail"
[ "$fail" -eq 0 ]

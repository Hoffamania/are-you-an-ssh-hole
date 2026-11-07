#!/bin/sh
# Unit tests for sshole-audit.sh.
# Loads the script as a library and exercises compute_verdict with fixtures,
# plus the shadow scanner against synthetic /etc/shadow files.
set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SSHOLE_LIB=1 . "$here/../sshole-audit.sh"

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
rm -rf "$tmp"

echo "-------------------------------------"
echo "passed: $pass   failed: $fail"
[ "$fail" -eq 0 ]

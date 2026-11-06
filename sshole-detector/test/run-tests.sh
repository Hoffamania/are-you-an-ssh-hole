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

# compute_verdict  libc crypt_star accounts sshd pam
check "musl + defect + '*' acct + sshd, no PAM shield = VULNERABLE" \
    VULNERABLE     "$(compute_verdict musl yes 1 yes not_shielded)"
check "glibc is never vulnerable" \
    NOT_VULNERABLE "$(compute_verdict glibc no 1 yes not_shielded)"
check "musl but crypt does not return '*' = NOT_VULNERABLE" \
    NOT_VULNERABLE "$(compute_verdict musl no 1 yes not_shielded)"
check "musl + defect but no '*' accounts = NOT_VULNERABLE" \
    NOT_VULNERABLE "$(compute_verdict musl yes 0 yes not_shielded)"
check "musl + defect + '*' acct but no sshd = NOT_VULNERABLE" \
    NOT_VULNERABLE "$(compute_verdict musl yes 1 no not_shielded)"
check "musl + defect + '*' acct + PAM shield = NEEDS_REVIEW" \
    NEEDS_REVIEW   "$(compute_verdict musl yes 1 yes shielded)"
check "shadow unreadable on musl+defect = NEEDS_REVIEW" \
    NEEDS_REVIEW   "$(compute_verdict musl yes __UNREADABLE__ yes not_shielded)"
check "unknown libc = NEEDS_REVIEW" \
    NEEDS_REVIEW   "$(compute_verdict unknown unknown 1 yes unknown)"

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

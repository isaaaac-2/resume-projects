#!/usr/bin/env bash
# ============================================================
# verify-hardening.sh
# Checks that all hardening steps are in place.
# Run this AFTER server-hardening.sh to confirm everything worked.
#
# USAGE:
#   chmod +x verify-hardening.sh
#   sudo ./verify-hardening.sh
# ============================================================

GREEN='\033[0;32m'
RED='\033[0;31m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS="${GREEN}[PASS]${NC}"
FAIL="${RED}[FAIL]${NC}"
WARN="${ORANGE}[WARN]${NC}"

pass=0; fail=0; warn=0

check_pass() { echo -e "  ${PASS} $1"; ((pass++)); }
check_fail() { echo -e "  ${FAIL} $1"; ((fail++)); }
check_warn() { echo -e "  ${WARN} $1"; ((warn++)); }
section()    { echo -e "\n${BLUE}── $1${NC}"; }

echo ""
echo "=============================================="
echo "  Server Hardening Verification"
echo "=============================================="

# ── UFW Firewall ─────────────────────────────────────────────
section "Firewall (UFW)"
if ufw status | grep -q "Status: active"; then
  check_pass "UFW is active"
else
  check_fail "UFW is NOT active"
fi

if ufw status | grep -q "22/tcp"; then
  check_fail "Port 22 is open — should be closed or changed to custom port"
else
  check_pass "Port 22 (default SSH) is NOT open"
fi

if ufw status | grep -q "443"; then
  check_pass "Port 443 (HTTPS) is open"
else
  check_warn "Port 443 is not open — HTTPS may not be working"
fi

# ── SSH Configuration ─────────────────────────────────────────
section "SSH Hardening"
if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
  check_pass "Root login disabled (PermitRootLogin no)"
else
  check_fail "Root login is NOT disabled"
fi

if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config; then
  check_pass "Password authentication disabled (key-only)"
else
  check_fail "Password authentication is still enabled"
fi

ssh_port=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}')
if [ "$ssh_port" != "22" ] && [ -n "$ssh_port" ]; then
  check_pass "SSH running on non-default port: $ssh_port"
else
  check_warn "SSH is on port 22 (consider changing to a custom port)"
fi

# ── Nginx ────────────────────────────────────────────────────
section "Nginx Web Server"
if systemctl is-active --quiet nginx; then
  check_pass "Nginx is running"
else
  check_fail "Nginx is NOT running"
fi

if nginx -t &>/dev/null; then
  check_pass "Nginx config is valid (nginx -t passed)"
else
  check_fail "Nginx config has errors"
fi

if grep -q "server_tokens off" /etc/nginx/sites-available/default; then
  check_pass "Server version hidden (server_tokens off)"
else
  check_warn "server_tokens is not set — Nginx version is visible in responses"
fi

if grep -q "Strict-Transport-Security" /etc/nginx/sites-available/default; then
  check_pass "HSTS header configured"
else
  check_warn "HSTS header not found — HTTPS enforcement not enforced by browser"
fi

if grep -q "X-Frame-Options" /etc/nginx/sites-available/default; then
  check_pass "X-Frame-Options header configured (clickjacking protection)"
else
  check_warn "X-Frame-Options header not configured"
fi

# ── SSL Certificate ───────────────────────────────────────────
section "SSL/TLS Certificate"
if command -v certbot &>/dev/null; then
  check_pass "Certbot is installed"
  cert_count=$(certbot certificates 2>/dev/null | grep -c "Certificate Name" || echo "0")
  if [ "$cert_count" -gt 0 ]; then
    check_pass "Let's Encrypt certificate is present ($cert_count cert(s))"
  else
    check_warn "No Certbot certificates found (may be using self-signed)"
  fi
else
  check_warn "Certbot not installed"
fi

# ── fail2ban ─────────────────────────────────────────────────
section "fail2ban (Brute-force Protection)"
if systemctl is-active --quiet fail2ban; then
  check_pass "fail2ban is running"
  banned=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
  check_pass "fail2ban sshd jail active — Currently banned IPs: ${banned:-0}"
else
  check_fail "fail2ban is NOT running"
fi

# ── Kernel Security ──────────────────────────────────────────
section "Kernel Hardening (sysctl)"
if sysctl net.ipv4.tcp_syncookies | grep -q "= 1"; then
  check_pass "SYN flood protection enabled (tcp_syncookies=1)"
else
  check_fail "SYN flood protection NOT enabled"
fi

if sysctl kernel.randomize_va_space | grep -q "= 2"; then
  check_pass "ASLR enabled (randomize_va_space=2)"
else
  check_fail "ASLR not fully enabled"
fi

if sysctl net.ipv4.conf.all.log_martians | grep -q "= 1"; then
  check_pass "Suspicious packet logging enabled"
else
  check_warn "Suspicious packet logging not enabled"
fi

# ── Unattended Upgrades ───────────────────────────────────────
section "Automatic Security Updates"
if dpkg -l unattended-upgrades &>/dev/null; then
  check_pass "unattended-upgrades package installed"
else
  check_warn "unattended-upgrades not installed"
fi

# ── Summary ───────────────────────────────────────────────────
total=$((pass + fail + warn))
echo ""
echo "=============================================="
echo "  Verification Summary"
echo "=============================================="
echo -e "  Total checks : $total"
echo -e "  ${GREEN}Passed${NC}       : $pass"
echo -e "  ${RED}Failed${NC}       : $fail"
echo -e "  ${ORANGE}Warnings${NC}     : $warn"
echo ""

if [ "$fail" -eq 0 ]; then
  echo -e "${GREEN}✓ All critical checks passed!${NC}"
else
  echo -e "${RED}✗ $fail check(s) failed — review output above.${NC}"
fi
echo ""

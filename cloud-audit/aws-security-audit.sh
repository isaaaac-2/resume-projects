#!/usr/bin/env bash
# ============================================================
# aws-security-audit.sh
# Automated AWS security audit script using the AWS CLI.
# Checks key CIS Benchmark controls and prints a colour-coded
# report to the terminal.
#
# REQUIREMENTS:
#   - AWS CLI v2 installed and configured (aws configure)
#   - An IAM user/role with SecurityAudit read-only policy
#   - jq installed (sudo apt install jq)
#
# USAGE:
#   chmod +x aws-security-audit.sh
#   ./aws-security-audit.sh
# ============================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────
RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'  # No colour / reset

PASS="${GREEN}[PASS]${NC}"
FAIL="${RED}[FAIL]${NC}"
WARN="${ORANGE}[WARN]${NC}"
INFO="${BLUE}[INFO]${NC}"

# ── Counters ─────────────────────────────────────────────────
pass_count=0
fail_count=0
warn_count=0

# ── Helper functions ─────────────────────────────────────────
check_pass() { echo -e "${PASS} $1"; ((pass_count++)); }
check_fail() { echo -e "${FAIL} $1"; ((fail_count++)); }
check_warn() { echo -e "${WARN} $1"; ((warn_count++)); }
section()    { echo -e "\n${BLUE}══ $1 ══${NC}"; }

# ── Pre-flight: Check dependencies ───────────────────────────
echo "=============================================="
echo "  AWS Cloud Security Audit Script"
echo "  CIS AWS Foundations Benchmark v1.5.0"
echo "=============================================="
echo ""

if ! command -v aws &>/dev/null; then
  echo -e "${RED}ERROR: AWS CLI is not installed. Run: sudo apt install awscli${NC}"
  exit 1
fi

if ! command -v jq &>/dev/null; then
  echo -e "${RED}ERROR: jq is not installed. Run: sudo apt install jq${NC}"
  exit 1
fi

echo -e "${INFO} AWS Identity: $(aws sts get-caller-identity --query 'Arn' --output text 2>/dev/null || echo 'Could not retrieve — check credentials')"
echo ""

# ─────────────────────────────────────────────────────────────
section "1. IAM — IDENTITY & ACCESS MANAGEMENT"
# ─────────────────────────────────────────────────────────────

# Check 1.1: MFA enabled on root account
echo -e "${INFO} Checking root account MFA..."
mfa_enabled=$(aws iam get-account-summary \
  --query 'SummaryMap.AccountMFAEnabled' \
  --output text 2>/dev/null)

if [ "$mfa_enabled" = "1" ]; then
  check_pass "CIS 1.5 — Root account MFA is enabled"
else
  check_fail "CIS 1.5 — Root account MFA is NOT enabled [CRITICAL]"
fi

# Check 1.2: No active root access keys
echo -e "${INFO} Checking root access keys..."
root_key_count=$(aws iam get-account-summary \
  --query 'SummaryMap.AccountAccessKeysPresent' \
  --output text 2>/dev/null)

if [ "$root_key_count" = "0" ]; then
  check_pass "CIS 1.4 — Root account has no active access keys"
else
  check_fail "CIS 1.4 — Root account has active access keys [HIGH]"
fi

# Check 1.3: Password policy exists and meets minimum requirements
echo -e "${INFO} Checking IAM password policy..."
min_length=$(aws iam get-account-password-policy \
  --query 'PasswordPolicy.MinimumPasswordLength' \
  --output text 2>/dev/null || echo "0")

if [ "$min_length" -ge 14 ] 2>/dev/null; then
  check_pass "CIS 1.8 — Password minimum length is $min_length characters (≥14 required)"
elif [ "$min_length" -eq "0" ]; then
  check_fail "CIS 1.8 — No password policy configured [LOW]"
else
  check_warn "CIS 1.8 — Password minimum length is $min_length (should be ≥14)"
fi

# Check 1.4: IAM users with AdministratorAccess
echo -e "${INFO} Checking for users with AdministratorAccess..."
admin_users=$(aws iam list-users --query 'Users[*].UserName' --output text 2>/dev/null | \
  tr '\t' '\n' | while read -r user; do
    policies=$(aws iam list-attached-user-policies --user-name "$user" \
      --query 'AttachedPolicies[*].PolicyName' --output text 2>/dev/null)
    if echo "$policies" | grep -q "AdministratorAccess"; then
      echo "$user"
    fi
  done)

if [ -z "$admin_users" ]; then
  check_pass "CIS 1.16 — No IAM users have AdministratorAccess attached directly"
else
  check_fail "CIS 1.16 — Users with AdministratorAccess: $admin_users [MEDIUM]"
fi

# ─────────────────────────────────────────────────────────────
section "2. NETWORK — EC2 SECURITY GROUPS"
# ─────────────────────────────────────────────────────────────

# Check 2.1: Security groups with SSH open to the world
echo -e "${INFO} Checking Security Groups for open SSH (port 22)..."
open_ssh_groups=$(aws ec2 describe-security-groups \
  --filters Name=ip-permission.from-port,Values=22 \
            Name=ip-permission.to-port,Values=22 \
            Name=ip-permission.cidr,Values='0.0.0.0/0' \
  --query 'SecurityGroups[*].[GroupId,GroupName]' \
  --output text 2>/dev/null)

if [ -z "$open_ssh_groups" ]; then
  check_pass "CIS 5.2 — No Security Groups allow SSH from 0.0.0.0/0"
else
  check_fail "CIS 5.2 — Security Groups with open SSH:\n$open_ssh_groups [CRITICAL]"
fi

# Check 2.2: Security groups with RDP open to the world
echo -e "${INFO} Checking Security Groups for open RDP (port 3389)..."
open_rdp_groups=$(aws ec2 describe-security-groups \
  --filters Name=ip-permission.from-port,Values=3389 \
            Name=ip-permission.to-port,Values=3389 \
            Name=ip-permission.cidr,Values='0.0.0.0/0' \
  --query 'SecurityGroups[*].[GroupId,GroupName]' \
  --output text 2>/dev/null)

if [ -z "$open_rdp_groups" ]; then
  check_pass "CIS 5.3 — No Security Groups allow RDP from 0.0.0.0/0"
else
  check_fail "CIS 5.3 — Security Groups with open RDP:\n$open_rdp_groups [CRITICAL]"
fi

# ─────────────────────────────────────────────────────────────
section "3. STORAGE — S3 BUCKET SECURITY"
# ─────────────────────────────────────────────────────────────

echo -e "${INFO} Checking S3 buckets for public access..."
aws s3api list-buckets --query 'Buckets[*].Name' --output text 2>/dev/null | \
  tr '\t' '\n' | while read -r bucket; do
    public_block=$(aws s3api get-public-access-block --bucket "$bucket" \
      --query 'PublicAccessBlockConfiguration.BlockPublicAcls' \
      --output text 2>/dev/null || echo "false")

    if [ "$public_block" = "True" ]; then
      check_pass "S3 — Bucket '$bucket' has Block Public Access enabled"
    else
      check_fail "S3 — Bucket '$bucket' does NOT have Block Public Access enabled [HIGH]"
    fi
  done

# ─────────────────────────────────────────────────────────────
section "4. LOGGING — CLOUDTRAIL"
# ─────────────────────────────────────────────────────────────

echo -e "${INFO} Checking CloudTrail status..."
trail_count=$(aws cloudtrail describe-trails \
  --include-shadow-trails \
  --query 'trailList | length(@)' \
  --output text 2>/dev/null)

if [ "$trail_count" -gt 0 ] 2>/dev/null; then
  is_multiregion=$(aws cloudtrail describe-trails \
    --query 'trailList[0].IsMultiRegionTrail' \
    --output text 2>/dev/null)

  if [ "$is_multiregion" = "True" ]; then
    check_pass "CIS 3.1 — CloudTrail is enabled and covers all regions"
  else
    check_warn "CIS 3.1 — CloudTrail exists but is NOT multi-region"
  fi
else
  check_fail "CIS 3.1 — No CloudTrail trails configured [HIGH]"
fi

# ─────────────────────────────────────────────────────────────
section "5. DATABASE — RDS"
# ─────────────────────────────────────────────────────────────

echo -e "${INFO} Checking RDS instances for public accessibility..."
public_rds=$(aws rds describe-db-instances \
  --query 'DBInstances[?PubliclyAccessible==`true`].[DBInstanceIdentifier]' \
  --output text 2>/dev/null)

if [ -z "$public_rds" ]; then
  check_pass "RDS — No publicly accessible database instances found"
else
  check_fail "RDS — Publicly accessible instances: $public_rds [MEDIUM]"
fi

# ─────────────────────────────────────────────────────────────
section "AUDIT SUMMARY"
# ─────────────────────────────────────────────────────────────

total=$((pass_count + fail_count + warn_count))
echo ""
echo -e "  Total checks : $total"
echo -e "  ${GREEN}Passed${NC}       : $pass_count"
echo -e "  ${RED}Failed${NC}       : $fail_count"
echo -e "  ${ORANGE}Warnings${NC}     : $warn_count"
echo ""

if [ "$fail_count" -eq 0 ]; then
  echo -e "${GREEN}✓ All critical checks passed. Review warnings above.${NC}"
else
  echo -e "${RED}✗ $fail_count check(s) failed. Review findings above and remediate.${NC}"
fi

echo ""
echo "Audit completed at $(date)"
echo "=============================================="

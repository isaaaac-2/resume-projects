# AWS Cloud Infrastructure Security Audit Report

**Target Environment:** Sample AWS Production Account (Simulated)  
**Audit Framework:** CIS AWS Foundations Benchmark v1.5.0 + OWASP Cloud Security  
**Audit Date:** January 2024  
**Auditor:** [Your Name]  
**Risk Rating Scale:** CRITICAL › HIGH › MEDIUM › LOW › INFORMATIONAL

---

## Executive Summary

A security audit of a sample AWS cloud environment was conducted to assess the current security posture against industry benchmarks. The audit covered Identity and Access Management (IAM), network security (EC2 Security Groups, VPCs), data storage (S3), logging, and encryption configurations.

**7 findings were identified:**

| Severity | Count |
|----------|-------|
| CRITICAL | 2 |
| HIGH | 2 |
| MEDIUM | 2 |
| LOW | 1 |
| **Total** | **7** |

---

## Scope

| Service | Components Reviewed |
|---------|-------------------|
| IAM | Root account, users, roles, policies, MFA |
| EC2 | Security Groups, key pairs, AMIs |
| S3 | Bucket ACLs, policies, encryption, versioning |
| VPC | NACLs, Flow Logs, subnet configurations |
| CloudTrail | Logging status, log integrity |
| RDS | Encryption, public accessibility |

---

## Findings

---

### FINDING-001 — Root Account Has No MFA Enabled
**Severity:** 🔴 CRITICAL  
**CIS Control:** 1.5 — Ensure MFA is enabled for the root account  
**Service:** IAM

**Description:**  
The AWS root account (the most privileged account in the entire AWS environment) does not have Multi-Factor Authentication (MFA) enabled. If the root account credentials are compromised through phishing, credential stuffing, or a data breach, an attacker gains unlimited access to all AWS resources with no additional barrier.

**Evidence:**
```
aws iam get-account-summary
Output: "AccountMFAEnabled": 0   ← Should be 1
```

**Remediation:**
```
1. Log into the AWS Console as root
2. Navigate to: Account → Security credentials → Multi-factor authentication
3. Click "Activate MFA" → Select "Virtual MFA device"
4. Scan the QR code with Google Authenticator or Authy
5. Enter two consecutive MFA codes to complete activation
```

**Impact if Exploited:** Total account takeover. Attacker can create backdoor users, exfiltrate all data, delete all resources, and run up unlimited charges.

---

### FINDING-002 — EC2 Security Group Allows Unrestricted SSH (0.0.0.0/0 on Port 22)
**Severity:** 🔴 CRITICAL  
**CIS Control:** 5.2 — Ensure no security groups allow ingress from 0.0.0.0/0 to port 22  
**Service:** EC2 / Security Groups

**Description:**  
The security group `sg-0abc123def456789` attached to the production EC2 instance allows inbound SSH (port 22) connections from any IP address on the internet (`0.0.0.0/0`). This exposes the server to automated brute-force attacks running continuously from botnets worldwide.

**Evidence:**
```bash
aws ec2 describe-security-groups --group-ids sg-0abc123def456789 \
  --query 'SecurityGroups[*].IpPermissions'

Output:
[
  {
    "FromPort": 22,
    "ToPort": 22,
    "IpProtocol": "tcp",
    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]   ← CRITICAL: open to the entire internet
  }
]
```

**Remediation:**
```bash
# Step 1: Remove the dangerous rule
aws ec2 revoke-security-group-ingress \
  --group-id sg-0abc123def456789 \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

# Step 2: Add a rule that allows SSH only from YOUR specific IP address
# Replace 197.210.x.x with your actual public IP (check: curl ifconfig.me)
aws ec2 authorize-security-group-ingress \
  --group-id sg-0abc123def456789 \
  --protocol tcp \
  --port 22 \
  --cidr 197.210.YOUR_IP/32

# Better alternative: Use AWS Systems Manager Session Manager (no SSH needed at all)
# This eliminates port 22 entirely
```

**Impact if Exploited:** Unauthorized server access, data exfiltration, ransomware deployment, server used as part of a botnet.

---

### FINDING-003 — S3 Bucket Has Public ACL (Block Public Access Disabled)
**Severity:** 🟠 HIGH  
**CIS Control:** 2.1.5 — Ensure S3 buckets use Block Public Access  
**Service:** S3

**Description:**  
The S3 bucket `prod-company-data-bucket` has Block Public Access disabled and has an ACL set to `public-read`. Any file uploaded to this bucket is publicly readable by the entire internet without authentication, including potentially sensitive documents, user data, or internal files.

**Evidence:**
```bash
aws s3api get-bucket-acl --bucket prod-company-data-bucket
# Output shows: "Permission": "READ", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"

aws s3api get-public-access-block --bucket prod-company-data-bucket
# Output: All four BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets = false
```

**Remediation:**
```bash
# Enable Block Public Access on the bucket
aws s3api put-public-access-block \
  --bucket prod-company-data-bucket \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Remove the public ACL
aws s3api put-bucket-acl \
  --bucket prod-company-data-bucket \
  --acl private
```

---

### FINDING-004 — CloudTrail Logging Disabled in Two Regions
**Severity:** 🟠 HIGH  
**CIS Control:** 3.1 — Ensure CloudTrail is enabled in all regions  
**Service:** CloudTrail

**Description:**  
AWS CloudTrail (the audit log for all API calls in your AWS account) is not enabled in `eu-west-1` and `ap-southeast-1`. Any attacker activity or accidental misconfiguration in those regions will leave no trace, making forensic investigation impossible.

**Evidence:**
```bash
aws cloudtrail describe-trails --region eu-west-1
# Output: "trailList": []   ← Empty — no trails configured

aws cloudtrail get-trail-status --name myTrail --region eu-west-1
# AccessDeniedException — trail does not exist
```

**Remediation:**
```bash
# Create a multi-region CloudTrail that covers ALL regions from one configuration
aws cloudtrail create-trail \
  --name org-wide-audit-trail \
  --s3-bucket-name my-cloudtrail-logs-bucket \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --include-global-service-events

# Start logging
aws cloudtrail start-logging --name org-wide-audit-trail
```

---

### FINDING-005 — IAM Users Have Overly Permissive Policies (AdministratorAccess)
**Severity:** 🟡 MEDIUM  
**CIS Control:** 1.16 — Ensure IAM policies are attached only to groups or roles  
**Service:** IAM

**Description:**  
Three IAM users have the `AdministratorAccess` managed policy attached directly to their user account. This violates the principle of least privilege — users should only have permissions required for their specific job function.

**Evidence:**
```bash
aws iam list-attached-user-policies --user-name john.developer
# Output includes: "PolicyName": "AdministratorAccess"
```

**Remediation:**
```bash
# 1. Remove AdministratorAccess from the user
aws iam detach-user-policy \
  --user-name john.developer \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 2. Create a role with only the permissions they actually need
# 3. Assign the scoped-down role instead
# Example: A developer only needs EC2 read + S3 read for their specific bucket:
aws iam create-policy \
  --policy-name developer-limited-access \
  --policy-document file://developer-policy.json
```

**developer-policy.json (least privilege example):**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "*",
        "arn:aws:s3:::dev-team-bucket",
        "arn:aws:s3:::dev-team-bucket/*"
      ]
    }
  ]
}
```

---

### FINDING-006 — RDS Database Instance Is Publicly Accessible
**Severity:** 🟡 MEDIUM  
**CIS Control:** Database instances should not be publicly accessible  
**Service:** RDS

**Description:**  
The RDS MySQL instance `prod-db-01` has `PubliclyAccessible` set to `true`, meaning the database endpoint is reachable from the internet. Even with password authentication, this creates unnecessary exposure.

**Evidence:**
```bash
aws rds describe-db-instances --db-instance-identifier prod-db-01 \
  --query 'DBInstances[*].PubliclyAccessible'
# Output: [true]   ← Should be false
```

**Remediation:**
```bash
# Modify the RDS instance to remove public accessibility
aws rds modify-db-instance \
  --db-instance-identifier prod-db-01 \
  --no-publicly-accessible \
  --apply-immediately

# Ensure the database security group only allows inbound 3306 from the app server's security group
# NOT from 0.0.0.0/0
```

---

### FINDING-007 — No Password Policy Configured for IAM Users
**Severity:** 🔵 LOW  
**CIS Control:** 1.8–1.11 — Password policy requirements  
**Service:** IAM

**Description:**  
No IAM account password policy has been configured, meaning users can set passwords of any length and complexity, including trivially guessable passwords.

**Remediation:**
```bash
aws iam update-account-password-policy \
  --minimum-password-length 14 \
  --require-symbols \
  --require-numbers \
  --require-uppercase-characters \
  --require-lowercase-characters \
  --allow-users-to-change-password \
  --max-password-age 90 \
  --password-reuse-prevention 12
```

---

## Risk Summary Matrix

| Finding | Severity | Ease of Exploit | Business Impact | Priority |
|---------|----------|----------------|-----------------|----------|
| FINDING-001: No MFA on root | CRITICAL | Easy | Catastrophic | Fix Today |
| FINDING-002: SSH open to internet | CRITICAL | Easy | Very High | Fix Today |
| FINDING-003: Public S3 bucket | HIGH | Easy | High | Fix This Week |
| FINDING-004: CloudTrail disabled | HIGH | N/A (visibility gap) | High | Fix This Week |
| FINDING-005: Over-privileged IAM | MEDIUM | Moderate | Medium | Fix This Month |
| FINDING-006: Public RDS | MEDIUM | Moderate | High | Fix This Week |
| FINDING-007: Weak password policy | LOW | Low | Low | Fix This Month |

---

## Recommendations Summary

1. **Enable MFA on all accounts** — especially root. This is free and takes 5 minutes.
2. **Restrict all Security Group rules** — no rule should ever use `0.0.0.0/0` on administrative ports (22, 3389, 3306).
3. **Enable Block Public Access globally** — set the S3 account-level block to prevent any bucket from being accidentally made public.
4. **Enable multi-region CloudTrail** — one trail with `--is-multi-region-trail` covers everything.
5. **Adopt least-privilege IAM** — nobody needs `AdministratorAccess` for day-to-day work.

---

## Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| AWS CLI | 2.x | Querying resource configurations |
| Nmap | 7.94 | Verifying exposed ports externally |
| AWS Security Hub | — | Automated compliance scoring |
| Prowler | 3.x | CIS benchmark automated checker |

---

*This report was produced as part of a personal cloud security audit project. The AWS environment audited is a simulated/lab environment created for educational purposes.*

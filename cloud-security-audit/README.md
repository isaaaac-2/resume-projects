# Cloud Infrastructure Security Audit — Simulated AWS Environment

A practical cloud security audit of a sample AWS environment, mapping findings to the **CIS AWS Foundations Benchmark v1.5.0** and **OWASP Cloud Security** guidelines. Includes an automated audit script, full written report with CLI evidence, and remediation commands for every finding.

---

## Project Overview

This project simulates the work a Junior Cloud Security Engineer would perform when auditing a new AWS account. It covers the most common and dangerous misconfigurations found in real production environments.

**7 findings identified across 5 AWS services:**

| Finding | Severity | Service |
|---------|----------|---------|
| Root account has no MFA | 🔴 CRITICAL | IAM |
| SSH port 22 open to 0.0.0.0/0 | 🔴 CRITICAL | EC2 Security Groups |
| S3 bucket publicly accessible | 🟠 HIGH | S3 |
| CloudTrail disabled in multiple regions | 🟠 HIGH | CloudTrail |
| Users with AdministratorAccess | 🟡 MEDIUM | IAM |
| RDS instance publicly accessible | 🟡 MEDIUM | RDS |
| No IAM password policy | 🔵 LOW | IAM |

---

## Files in This Repository

```
├── README.md                  ← You are here
├── AUDIT-REPORT.md            ← Full written audit report with evidence and remediation
├── aws-security-audit.sh      ← Automated bash script that runs the checks via AWS CLI
└── findings/
    ├── finding-001-mfa.md     ← Deep dive: Root MFA
    ├── finding-002-ssh.md     ← Deep dive: Open SSH Security Group
    └── ...                    ← One file per finding
```

---

## Running the Automated Audit Script

The `aws-security-audit.sh` script checks the most critical CIS controls automatically using the AWS CLI.

### Prerequisites

```bash
# 1. Install AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip && sudo ./aws/install

# 2. Install jq (JSON processor)
sudo apt install jq -y

# 3. Configure AWS credentials
#    You need an IAM user with the SecurityAudit managed policy (read-only)
aws configure
# Enter: Access Key ID, Secret Access Key, Region (e.g. us-east-1), Output format (json)
```

### Run the Audit

```bash
# Make the script executable
chmod +x aws-security-audit.sh

# Run it
./aws-security-audit.sh
```

### Sample Output

```
==============================================
  AWS Cloud Security Audit Script
  CIS AWS Foundations Benchmark v1.5.0
==============================================

[INFO] AWS Identity: arn:aws:iam::123456789012:user/audit-user

══ 1. IAM — IDENTITY & ACCESS MANAGEMENT ══
[FAIL] CIS 1.5 — Root account MFA is NOT enabled [CRITICAL]
[PASS] CIS 1.4 — Root account has no active access keys
[FAIL] CIS 1.8 — No password policy configured [LOW]

══ 2. NETWORK — EC2 SECURITY GROUPS ══
[FAIL] CIS 5.2 — Security Groups with open SSH:
       sg-0abc123def456789    launch-wizard-1

══ 3. STORAGE — S3 BUCKET SECURITY ══
[FAIL] S3 — Bucket 'prod-data-bucket' does NOT have Block Public Access enabled [HIGH]

══ 4. LOGGING — CLOUDTRAIL ══
[PASS] CIS 3.1 — CloudTrail is enabled and covers all regions

══ 5. DATABASE — RDS ══
[FAIL] RDS — Publicly accessible instances: prod-db-01 [MEDIUM]

══ AUDIT SUMMARY ══
  Total checks : 8
  Passed       : 3
  Failed       : 5
  Warnings     : 0

✗ 5 check(s) failed. Review findings above and remediate.
==============================================
```

---

## Using AWS Free Tier for Practice (No Cost)

You can run this audit against a real AWS account for free:

1. Create a free AWS account at [aws.amazon.com](https://aws.amazon.com/free/)
2. Create an IAM user with the `SecurityAudit` policy (read-only, safe)
3. Set up a few resources (1 EC2 t2.micro, 1 S3 bucket) in the Free Tier
4. Run the script and see real results
5. Practice the remediation commands

---

## Key Security Concepts Demonstrated

**Principle of Least Privilege** — Users and services should only have the minimum permissions needed for their specific task. Demonstrated in FINDING-005 (IAM over-permissions).

**Defense in Depth** — Security should be layered. Demonstrated by requiring both MFA *and* strong passwords, not either/or.

**CIS Benchmarks** — The Center for Internet Security publishes scored configuration guidelines. CIS AWS Foundations Benchmark is the industry standard for AWS security assessment.

**OWASP Cloud Security** — OWASP's cloud security project maps common web application security risks to cloud infrastructure contexts.

---

## References

- [CIS AWS Foundations Benchmark v1.5.0](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS Security Best Practices](https://docs.aws.amazon.com/security/latest/ug/security-best-practices.html)
- [OWASP Cloud Security Project](https://owasp.org/www-project-cloud-security/)
- [Prowler — Open-source AWS security tool](https://github.com/prowler-cloud/prowler)
- [AWS IAM Security Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)

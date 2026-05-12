# Automated Vulnerability Scanner Pipeline

A CI/CD security pipeline built with **GitHub Actions**, **Trivy**, and **Snyk** that automatically scans source code, dependencies, and Docker images for known vulnerabilities on every push.

---

## What This Does

Every time code is pushed to this repository, the pipeline automatically:

1. **Trivy (Filesystem Scan)** — Scans all source files and dependency lock files for CVEs listed in the NVD, OSV, and GitHub Advisory databases
2. **Trivy (Image Scan)** — Builds the Docker image from the `Dockerfile` and scans the container layers for vulnerabilities
3. **Snyk (Dependency Scan)** — Checks `package.json` dependencies against Snyk's vulnerability database
4. **Summary Report** — Writes a structured Markdown summary to the GitHub Actions job page

Results are automatically uploaded to the **Security → Code Scanning** tab in GitHub, where findings are tracked, triaged, and dismissed with audit history.

---

## Pipeline Architecture

```
Git Push / Pull Request
        │
        ▼
┌─────────────────────────────────────────────────────┐
│              GitHub Actions Workflow                │
│                                                     │
│  ┌──────────────────┐   ┌──────────────────────┐   │
│  │  Trivy FS Scan   │   │ Trivy Image Scan     │   │
│  │  (source + deps) │   │ (Docker container)   │   │
│  └────────┬─────────┘   └──────────┬───────────┘   │
│           │                        │               │
│  ┌────────▼────────────────────────▼───────────┐   │
│  │          Snyk Dependency Scan               │   │
│  └────────────────────┬────────────────────────┘   │
│                       │                            │
│  ┌────────────────────▼────────────────────────┐   │
│  │         SARIF Upload → GitHub Security      │   │
│  └─────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

---

## Tools & Technologies

| Tool | Purpose |
|------|---------|
| GitHub Actions | Orchestrates the entire pipeline |
| Trivy (Aqua Security) | CVE scanning for filesystems and container images |
| Snyk | Open-source dependency vulnerability detection |
| SARIF | Standard format for uploading security findings to GitHub |
| Docker | Container build and image scanning target |

---

## Setup Instructions

### 1. Fork or Clone This Repository

```bash
git clone https://github.com/isaaaac-2/automated-vuln-scanner.git
cd automated-vuln-scanner
```

### 2. Add Your Snyk API Token as a GitHub Secret

Snyk requires an API token to run scans.

1. Create a free account at [snyk.io](https://snyk.io)
2. Go to **Account Settings → API Token** and copy your token
3. In your GitHub repository: **Settings → Secrets and Variables → Actions → New repository secret**
4. Name: `SNYK_TOKEN` — Value: your Snyk token

### 3. Enable GitHub Advanced Security (for SARIF uploads)

For public repositories, this is **free and enabled by default**.  
Go to **Settings → Code Security and Analysis** and enable **Code scanning**.

### 4. Push to Trigger the Pipeline

```bash
git add .
git commit -m "feat: initial security pipeline setup"
git push origin main
```

Then go to the **Actions** tab in your repository to watch the pipeline run.

---

## Running Trivy Locally

You can run the same scanner on your local machine before pushing:

```bash
# Install Trivy (Ubuntu/Debian)
sudo apt-get install wget apt-transport-https gnupg lsb-release -y
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | \
  sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install trivy -y

# Scan the current directory
trivy fs .

# Scan a Docker image
trivy image node:20-alpine

# Scan with only CRITICAL and HIGH severity
trivy fs --severity CRITICAL,HIGH .
```

---

## Sample Output

```
2024-01-15T10:23:01.432Z  INFO  Vulnerability scanning is enabled
2024-01-15T10:23:02.112Z  INFO  Detected OS: alpine 3.18.4

┌────────────────────┬────────────────┬──────────┬──────────────────────────────────────────┐
│      Library       │  Vulnerability │ Severity │                  Title                   │
├────────────────────┼────────────────┼──────────┼──────────────────────────────────────────┤
│ express            │ CVE-2024-29041 │ MEDIUM   │ Open redirect in Express                 │
│ semver             │ CVE-2022-25883 │ HIGH     │ Regular Expression Denial of Service      │
└────────────────────┴────────────────┴──────────┴──────────────────────────────────────────┘

Total: 2 (HIGH: 1, MEDIUM: 1)
```

---

## Key Learnings

- How CI/CD pipelines are structured using YAML workflow files
- How container image scanning differs from source code scanning (layers vs. files)
- The SARIF format and how security tools report findings to code platforms
- How to use GitHub Secrets to protect API tokens in pipelines
- The OWASP principle of shifting security **left** (catching vulnerabilities before deployment)

---

## References

- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Snyk GitHub Action](https://github.com/snyk/actions)
- [GitHub Code Scanning Docs](https://docs.github.com/en/code-security/code-scanning)
- [OWASP DevSecOps Guideline](https://owasp.org/www-project-devsecops-guideline/)

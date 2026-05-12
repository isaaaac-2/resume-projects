# Hardened Linux Web Server

A production-grade Nginx web server configured on Ubuntu 22.04 LTS with full firewall rules, SSL/TLS certificates, brute-force protection, kernel hardening, and automated security validation. Built to demonstrate Linux server administration and DevSecOps hardening practices.

---

## What Was Built

| Component | Configuration |
|-----------|--------------|
| **OS** | Ubuntu 22.04 LTS (in Oracle VirtualBox) |
| **Web server** | Nginx with security headers, HTTPS redirect, rate limiting |
| **Firewall** | UFW — only ports 443 (HTTPS), 80 (HTTP→redirect), and custom SSH open |
| **SSH** | Key-only auth, no root login, custom port, restricted ciphers |
| **SSL/TLS** | Let's Encrypt (or self-signed for local VM) — TLS 1.2/1.3 only |
| **Brute-force protection** | fail2ban — auto-bans after 3 failed SSH attempts for 24 hours |
| **Kernel hardening** | SYN cookie protection, ASLR, IP spoofing prevention via sysctl |
| **Auto-updates** | unattended-upgrades for daily security patches |
| **Audit** | Lynis hardening index: 74/100 |

---

## Security Headers Applied

All HTTP responses include these security headers, verified via [securityheaders.com](https://securityheaders.com):

| Header | Value | Protection |
|--------|-------|-----------|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Forces HTTPS forever, prevents SSL stripping |
| `X-Frame-Options` | `SAMEORIGIN` | Prevents clickjacking |
| `X-Content-Type-Options` | `nosniff` | Prevents MIME type sniffing |
| `X-XSS-Protection` | `1; mode=block` | Legacy XSS protection |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limits referrer information leakage |
| `Content-Security-Policy` | `default-src 'self'` | Prevents XSS and data injection |
| `server_tokens` | `off` | Hides Nginx version from attackers |

---

## UFW Firewall Rules

```
Status: active

To                         Action      From
--                         ------      ----
2222/tcp                   ALLOW IN    Anywhere    # Custom SSH port
80/tcp                     ALLOW IN    Anywhere    # HTTP (redirects to HTTPS)
443/tcp                    ALLOW IN    Anywhere    # HTTPS
Nginx Full                 DENY        Anywhere    # Block default rules
22/tcp                     DENY        Anywhere    # Default SSH — BLOCKED
```

---

## Setup Guide (Follow These Exact Steps)

### Prerequisites
- Oracle VirtualBox installed: [virtualbox.org](https://www.virtualbox.org/wiki/Downloads)
- Ubuntu 22.04 ISO downloaded: [ubuntu.com/download/server](https://ubuntu.com/download/server)

### Step 1: Create the VM in VirtualBox

```
1. Open VirtualBox → New
2. Name: ubuntu-server, Type: Linux, Version: Ubuntu (64-bit)
3. RAM: 2048 MB minimum
4. Disk: 20 GB (dynamically allocated)
5. Attach the Ubuntu ISO to the optical drive
6. Boot and follow the Ubuntu Server install wizard
7. Choose: Install OpenSSH server ✓ during setup
```

### Step 2: SSH into the VM from your host machine

```bash
# In VirtualBox: Settings → Network → Adapter 1 → Bridged Adapter
# Or use Port Forwarding: Host 2222 → Guest 22

ssh your-username@192.168.x.x   # Find VM IP with: ip addr show
```

### Step 3: Clone this repository and run the hardening script

```bash
# Install git
sudo apt install git -y

# Clone this repo
git clone https://github.com/isaaaac-2/linux-server-hardening.git
cd linux-server-hardening

# Make scripts executable
chmod +x server-hardening.sh verify-hardening.sh

# Edit the config variables at the top of the script
nano server-hardening.sh
# Change: YOUR_DOMAIN, YOUR_EMAIL, SSH_PORT, ADMIN_USER

# Run the hardening script
sudo ./server-hardening.sh
```

### Step 4: Verify everything worked

```bash
sudo ./verify-hardening.sh
```

### Step 5: Test the security headers

```bash
# Check security headers from the command line
curl -sI http://localhost | grep -E "X-Frame|X-Content|Strict|server:"

# Or paste your IP into: https://securityheaders.com
```

---

## fail2ban in Action

After setup, you can watch fail2ban catch and ban attackers in real time:

```bash
# Watch the SSH jail — shows banned IPs
sudo fail2ban-client status sshd

# Watch the log in real time
sudo tail -f /var/log/fail2ban.log

# Manually unban an IP (if you accidentally lock yourself out)
sudo fail2ban-client set sshd unbanip YOUR_IP_ADDRESS
```

---

## Lynis Security Audit

[Lynis](https://cisofy.com/lynis/) is an open-source security auditing tool that scores your Linux system:

```bash
# Run the audit
sudo lynis audit system

# View the full report
sudo cat /var/log/lynis.log

# View just the warnings and suggestions
sudo grep -E "WARNING|SUGGESTION" /var/log/lynis-report.dat
```

**Score achieved after hardening: 74/100**  
Key areas contributing to the score: SSH hardening, file permissions, kernel settings, and firewall configuration.

---

## Key Concepts Demonstrated

**Defence in Depth** — Multiple layers of security: firewall blocks most attacks before they reach Nginx; Nginx rate-limits the rest; fail2ban bans persistent attackers; SSH key auth prevents credential attacks.

**Principle of Least Privilege** — No root SSH, non-default SSH port, only necessary ports open, services run with minimal permissions.

**CIS Benchmark Alignment** — Configuration choices map to CIS Ubuntu Server Benchmark controls for SSH, network, and filesystem settings.

**Shift-Left Security** — Security is built in during server provisioning, not added later.

---

## References

- [CIS Ubuntu Linux 22.04 Benchmark](https://www.cisecurity.org/benchmark/ubuntu_linux)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/) — Nginx TLS settings
- [Lynis Documentation](https://cisofy.com/documentation/lynis/)
- [UFW Documentation](https://help.ubuntu.com/community/UFW)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)

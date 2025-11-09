# Usage Guide

Comprehensive guide for using the Linux Security Vulnerability Analyzer.

## Table of Contents

- [Basic Usage](#basic-usage)
- [Running the Audit](#running-the-audit)
- [Understanding the Report](#understanding-the-report)
- [Interpreting Findings](#interpreting-findings)
- [Using Remediation Scripts](#using-remediation-scripts)
- [Advanced Usage](#advanced-usage)
- [Best Practices](#best-practices)

## Basic Usage

### Standard Audit (Recommended)

Run with root privileges for complete audit:

```bash
sudo ./linux_security_audit.sh
```

### Limited Mode

Run without root for limited checks:

```bash
./linux_security_audit.sh
```

When prompted, choose whether to continue with limited checks.

## Running the Audit

### Step-by-Step Execution

1. **Navigate to Script Directory**
   ```bash
   cd /path/to/lin_dit
   ```

2. **Run the Audit**
   ```bash
   sudo ./linux_security_audit.sh
   ```

3. **Monitor Progress**
   The script will display 11 phases:
   - Phase 1: System Information Gathering
   - Phase 2: User and Authentication Security
   - Phase 3: Network Security Assessment
   - Phase 4: File System and Permissions
   - Phase 5: Service and Process Analysis
   - Phase 6: Package Management and CVE Detection
   - Phase 7: Kernel and System Configuration
   - Phase 8: Log and Audit Analysis
   - Phase 9: Firewall and Security Tools
   - Phase 10: Compliance and Best Practices
   - Phase 11: CVE Analysis and Reporting

4. **Review Results**
   After completion, check:
   - Console summary
   - Report file: `security_audit_report_YYYYMMDD_HHMMSS.txt`
   - Remediation script (if CVEs found): `fix_critical_cves_YYYYMMDD_HHMMSS.sh`

## Understanding the Report

### Report Structure

The report is organized into sections:

```
================================================================================
  LINUX SECURITY AUDIT REPORT WITH CVE ANALYSIS
================================================================================

Audit Date: YYYY-MM-DD HH:MM:SS
Script Version: 2.0.0
Hostname: your-hostname
Operating System: Ubuntu 22.04
OS Family: Debian
Package Manager: apt
Privileged Mode: true

[10 Security Check Sections]

[CVE Report Section]

[Executive Summary]
```

### Finding Format

Each finding includes:

```
[SEVERITY] Finding Title
Description: Detailed description of the issue
Remediation: Steps to fix the issue
```

### Severity Levels

- **[CRITICAL]**: Immediate action required
  - Examples: Root password empty, remote root login enabled
  - Timeline: Fix immediately

- **[HIGH]**: Address within 24 hours
  - Examples: Multiple users with UID 0, weak SSH configuration
  - Timeline: 24-48 hours

- **[MEDIUM]**: Address within 1 week
  - Examples: Missing security updates, weak file permissions
  - Timeline: 1-2 weeks

- **[LOW]**: Address during regular maintenance
  - Examples: Missing optional security tools, minor misconfigurations
  - Timeline: Next maintenance window

- **[INFO]**: Informational findings
  - Examples: Installed packages, system configuration details
  - Timeline: No action required

## Interpreting Findings

### Security Check Categories

#### 1. System Information

Reports on:
- Operating system version
- Kernel version
- Security update status
- Support status (ESM, LTS)

**Key Indicators:**
- Outdated OS version
- Kernel vulnerabilities
- Missing security updates

#### 2. User & Authentication

Checks for:
- Multiple root users (UID 0)
- Users with empty passwords
- Weak password policies
- Sudo configuration
- Active user sessions

**Key Indicators:**
- Non-standard root accounts
- Passwordless accounts
- Unrestricted sudo access

#### 3. Network Security

Examines:
- Open ports and listening services
- SSH configuration
- Network services security
- IP forwarding status
- Network interfaces

**Key Indicators:**
- Unnecessary open ports
- Weak SSH configuration
- Insecure network services

#### 4. File System & Permissions

Analyzes:
- SUID/SGID files
- World-writable files
- Sensitive file permissions
- Mount point security
- Disk usage

**Key Indicators:**
- Unusual SUID binaries
- World-writable system files
- Weak permissions on critical files

#### 5. Service & Process

Reviews:
- Running services
- Listening processes
- Service configurations
- Unnecessary services
- Service security

**Key Indicators:**
- Unneeded services running
- Services running as root
- Insecure service configurations

#### 6. Package Management

Checks:
- Installed packages
- Available security updates
- Package vulnerabilities
- Package sources
- Update history

**Key Indicators:**
- Outdated packages
- Available security updates
- Vulnerable package versions

#### 7. Kernel Security

Assesses:
- Kernel version
- Kernel modules
- Kernel parameters
- Security features (SELinux, AppArmor)
- Kernel vulnerabilities

**Key Indicators:**
- Outdated kernel
- Disabled security features
- Insecure kernel parameters

#### 8. Logs & Auditing

Examines:
- Log file configuration
- Audit daemon status
- Log rotation
- Suspicious log entries
- Logging coverage

**Key Indicators:**
- Disabled logging
- Missing audit daemon
- Suspicious activities in logs

#### 9. Firewall & Security Tools

Checks:
- Firewall status (UFW, firewalld, iptables)
- Security tools (fail2ban, rkhunter, etc.)
- Intrusion detection systems
- Security software versions

**Key Indicators:**
- Firewall disabled
- Missing security tools
- Outdated security software

#### 10. Compliance & Best Practices

Validates:
- CIS benchmark alignment
- Industry best practices
- Security hardening status
- Configuration compliance

**Key Indicators:**
- Non-compliant configurations
- Missing hardening measures
- Deviations from standards

### CVE Report

#### CVE Entry Format

```
[SEVERITY] CVE-ID | CVSS: X.X | Package: package-name
  Description: Vulnerability description
  Fixed Version: version-number
  Remediation: Command to fix
```

#### CVSS Score Interpretation

- **9.0 - 10.0 (CRITICAL)**: Severe vulnerability
  - Often remotely exploitable
  - Could lead to complete system compromise
  - Patch immediately

- **7.0 - 8.9 (HIGH)**: Serious vulnerability
  - May be remotely exploitable
  - Could lead to significant compromise
  - Patch within 24 hours

- **4.0 - 6.9 (MEDIUM)**: Moderate vulnerability
  - Often requires local access
  - Limited impact
  - Patch within 1 week

- **0.1 - 3.9 (LOW)**: Minor vulnerability
  - Low impact
  - Difficult to exploit
  - Patch during regular maintenance

## Using Remediation Scripts

### Overview

When critical or high CVEs are detected, an automated remediation script is generated:

`fix_critical_cves_YYYYMMDD_HHMMSS.sh`

### Before Running

**IMPORTANT**: Always review the script before execution!

```bash
# View the remediation script
cat fix_critical_cves_*.sh

# Or use a text editor
nano fix_critical_cves_*.sh
```

### Execution Steps

1. **Backup Your System**
   ```bash
   # Create system backup or snapshot
   sudo rsync -av / /backup/location
   ```

2. **Review the Script**
   ```bash
   cat fix_critical_cves_*.sh
   ```

3. **Make Script Executable** (if needed)
   ```bash
   chmod +x fix_critical_cves_*.sh
   ```

4. **Run the Remediation**
   ```bash
   sudo ./fix_critical_cves_*.sh
   ```

5. **Monitor Execution**
   Watch for errors during execution

6. **Verify Fixes**
   ```bash
   # Re-run audit to verify
   sudo ./linux_security_audit.sh
   ```

7. **Reboot if Required**
   ```bash
   # If kernel or critical packages were updated
   sudo reboot
   ```

### Remediation Script Contents

The script contains:

- Header with date and system information
- Privilege check
- Individual fix commands for each CVE
- Update commands specific to your package manager
- Completion message

Example structure:
```bash
#!/bin/bash
# Critical CVE Remediation Script
# Date: 2024-11-09
# System: Ubuntu 22.04

if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Fix for CVE-2024-XXXX (CVSS: 9.5 - CRITICAL)
echo "Fixing CVE-2024-XXXX..."
sudo apt-get update && sudo apt-get install --only-upgrade package-name

# Additional fixes...

echo "Remediation complete."
```

## Advanced Usage

### Automated Audits

Set up cron jobs for regular audits:

```bash
# Edit root's crontab
sudo crontab -e

# Add weekly audit (Sunday at 2 AM)
0 2 * * 0 /path/to/linux_security_audit.sh > /var/log/security_audit.log 2>&1

# Add monthly audit with email notification
0 2 1 * * /path/to/linux_security_audit.sh && mail -s "Security Audit" admin@example.com < security_audit_report_*.txt
```

### Filtering Specific Checks

While the script runs all checks by default, you can modify it to focus on specific areas. See CONTRIBUTING.md for code modification guidelines.

### Integration with SIEM

Export findings to SIEM systems:

```bash
# Convert report to syslog format
cat security_audit_report_*.txt | logger -t security_audit -p local0.info

# Send to remote syslog
cat security_audit_report_*.txt | nc syslog-server 514
```

### Custom Reporting

Extract specific findings:

```bash
# Extract all CRITICAL findings
grep "\[CRITICAL\]" security_audit_report_*.txt

# Extract CVE summary
grep -A 5 "CVE SUMMARY" security_audit_report_*.txt

# Count findings by severity
echo "Critical: $(grep -c "\[CRITICAL\]" security_audit_report_*.txt)"
echo "High: $(grep -c "\[HIGH\]" security_audit_report_*.txt)"
```

## Best Practices

### Regular Audits

- **Frequency**: Monthly minimum, weekly recommended
- **After Changes**: Run after system changes or updates
- **Before Deployment**: Audit before production deployment
- **Compliance**: Schedule around compliance requirements

### Report Management

1. **Store Securely**
   ```bash
   chmod 600 security_audit_report_*.txt
   mv security_audit_report_*.txt /secure/location/
   ```

2. **Archive Old Reports**
   ```bash
   mkdir -p /var/security/archives/$(date +%Y)
   gzip security_audit_report_*.txt
   mv security_audit_report_*.txt.gz /var/security/archives/$(date +%Y)/
   ```

3. **Track Changes**
   ```bash
   # Compare with previous report
   diff security_audit_report_old.txt security_audit_report_new.txt
   ```

### Remediation Workflow

1. **Prioritize**: Address CRITICAL and HIGH first
2. **Test**: Test fixes in non-production first
3. **Backup**: Always backup before making changes
4. **Document**: Document what was changed and why
5. **Verify**: Re-run audit to confirm fixes
6. **Monitor**: Watch for any issues post-remediation

### Security Hygiene

- Run audits regularly
- Review all findings, not just critical
- Keep audit history for trending
- Address findings promptly
- Update the audit tool regularly
- Review remediation scripts before running
- Maintain change logs

### Compliance Tracking

Use audit reports for compliance:

- **PCI DSS**: Track security configurations
- **HIPAA**: Document security controls
- **SOC 2**: Evidence of security monitoring
- **ISO 27001**: Security audit evidence
- **CIS Benchmarks**: Compliance validation

## Common Scenarios

### Scenario 1: First-Time Audit

Many findings are normal on first run:

1. Review all CRITICAL findings first
2. Create remediation plan
3. Address HIGH findings next
4. Schedule MEDIUM/LOW fixes
5. Re-audit after fixes

### Scenario 2: Post-Update Audit

After system updates:

1. Run audit to verify no new issues
2. Check for new CVEs
3. Verify updates applied correctly
4. Confirm no broken configurations

### Scenario 3: Pre-Production Audit

Before deploying to production:

1. Run full audit
2. Ensure no CRITICAL findings
3. Address all HIGH findings
4. Document remaining findings
5. Get sign-off on acceptable risks

### Scenario 4: Incident Response

After security incident:

1. Run immediate audit
2. Compare with previous audit
3. Identify changes
4. Look for indicators of compromise
5. Document findings for investigation

## Troubleshooting

### No Output Generated

- Check disk space
- Verify write permissions
- Run with `bash -x` for debugging

### Incomplete Audit

- Ensure root privileges
- Check for missing dependencies
- Review error messages

### False Positives

- Review finding context
- Understand your environment
- Document accepted risks
- Consider customizing checks

## Next Steps

- See [README.md](../README.md) for overview
- See [INSTALL.md](../INSTALL.md) for installation
- See [docs/CVE_DETECTION.md](CVE_DETECTION.md) for CVE details
- See [docs/COMPLIANCE.md](COMPLIANCE.md) for compliance guidance

---

For questions or issues, open a GitHub issue or consult the documentation.

# CVE Detection Guide

Comprehensive guide to CVE detection capabilities and CVSS scoring in the Linux Security Vulnerability Analyzer.

## Table of Contents

- [Overview](#overview)
- [CVE Detection Methods](#cve-detection-methods)
- [CVSS Scoring](#cvss-scoring)
- [Distribution-Specific Detection](#distribution-specific-detection)
- [CVE Database](#cve-database)
- [Remediation](#remediation)
- [Limitations](#limitations)

## Overview

The Linux Security Vulnerability Analyzer integrates CVE (Common Vulnerabilities and Exposures) detection to identify known security vulnerabilities in installed packages.

### What is CVE?

CVE is a system for identifying and cataloging publicly known cybersecurity vulnerabilities:

- **CVE-ID Format**: CVE-YYYY-NNNNN (e.g., CVE-2024-12345)
- **Maintained By**: MITRE Corporation
- **Purpose**: Standardized vulnerability identification
- **Usage**: Referenced across security tools and databases

### What is CVSS?

CVSS (Common Vulnerability Scoring System) provides standardized severity ratings:

- **Scale**: 0.0 to 10.0
- **Purpose**: Quantify vulnerability severity
- **Version**: CVSS v3.x used when available
- **Factors**: Exploitability, impact, scope

## CVE Detection Methods

### Detection Process

1. **Package Enumeration**
   - Lists all installed packages
   - Captures package versions
   - Identifies package sources

2. **Security Advisory Query**
   - Queries distribution's security advisories
   - Checks package-specific vulnerabilities
   - Retrieves CVE assignments

3. **Version Matching**
   - Compares installed vs. fixed versions
   - Identifies vulnerable packages
   - Determines fix availability

4. **CVSS Score Retrieval**
   - Fetches CVSS scores from advisories
   - Calculates severity ratings
   - Prioritizes vulnerabilities

5. **Remediation Generation**
   - Creates fix commands
   - Generates remediation scripts
   - Provides upgrade paths

### Detection Accuracy

Accuracy depends on:

- **Distribution Support**: Quality of security advisories
- **Package Manager**: Availability of security metadata
- **Internet Connectivity**: Access to advisory databases
- **Update Status**: Currency of security feeds

## CVSS Scoring

### Severity Ratings

The tool categorizes CVEs by CVSS score:

| CVSS Score | Severity | Color | Priority | Timeline |
|------------|----------|-------|----------|----------|
| 9.0 - 10.0 | CRITICAL | Red | P0 | Immediate |
| 7.0 - 8.9  | HIGH | Orange | P1 | 24 hours |
| 4.0 - 6.9  | MEDIUM | Yellow | P2 | 1 week |
| 0.1 - 3.9  | LOW | Blue | P3 | Next maintenance |

### CVSS Metrics

#### Base Score Components

**Attack Vector (AV)**
- Network (N): Remotely exploitable
- Adjacent (A): Same network required
- Local (L): Local access required
- Physical (P): Physical access required

**Attack Complexity (AC)**
- Low (L): Easy to exploit
- High (H): Difficult to exploit

**Privileges Required (PR)**
- None (N): No privileges needed
- Low (L): Basic user privileges
- High (H): Admin/root required

**User Interaction (UI)**
- None (N): No user interaction
- Required (R): User action needed

**Impact Metrics**
- Confidentiality Impact (C)
- Integrity Impact (I)
- Availability Impact (A)

### Example CVE Analysis

```
CVE-2024-12345 | CVSS: 9.8 (CRITICAL)
- Attack Vector: Network
- Attack Complexity: Low
- Privileges Required: None
- User Interaction: None
- Confidentiality: High
- Integrity: High
- Availability: High

Translation: Remotely exploitable, no authentication required,
complete system compromise possible. PATCH IMMEDIATELY.
```

## Distribution-Specific Detection

### Debian / Ubuntu

**Tools Used:**
- `apt list --upgradable`
- `debsecan` (if installed)
- `apt-show-versions` (if installed)

**Advisory Sources:**
- Ubuntu Security Notices (USN)
- Debian Security Advisory (DSA)

**Detection Method:**
```bash
apt list --upgradable 2>/dev/null | grep -i security
```

**Example Output:**
```
libssl1.1/focal-security 1.1.1f-1ubuntu2.20 amd64 [upgradable from: 1.1.1f-1ubuntu2.19]
```

**Enhanced Detection (with debsecan):**
```bash
debsecan --suite focal --only-fixed
```

### RHEL / CentOS / Rocky / AlmaLinux

**Tools Used:**
- `yum updateinfo` (RHEL 7/CentOS 7)
- `dnf updateinfo` (RHEL 8+)

**Advisory Sources:**
- Red Hat Security Advisories (RHSA)
- CentOS Security Advisories

**Detection Method (RHEL 7):**
```bash
yum updateinfo list cves
yum check-update --security
```

**Detection Method (RHEL 8+):**
```bash
dnf updateinfo list cves
dnf check-update --security
```

**Example Output:**
```
CVE-2024-1234  Important/Sec.  openssl-1.1.1k-7.el8_6
CVE-2024-5678  Critical/Sec.   kernel-4.18.0-372.32.1.el8_6
```

### Fedora

**Tools Used:**
- `dnf updateinfo`

**Advisory Sources:**
- Fedora Security Advisories (FEDORA-SA)

**Detection Method:**
```bash
dnf updateinfo list --security
dnf updateinfo list cves
```

### SUSE / openSUSE

**Tools Used:**
- `zypper list-patches`

**Advisory Sources:**
- SUSE Security Announcements (SUSE-SA)

**Detection Method:**
```bash
zypper list-patches --category security
zypper list-patches --cve
```

**Example Output:**
```
SUSE-SLE-Module-Basesystem-15-SP4-2024:1234 | security | CVE-2024-1234
```

## CVE Database

### Local CVE Cache

The tool maintains a local CVE cache:

**Location**: `.cve_cache/`

**Purpose:**
- Faster subsequent scans
- Offline reference
- Historical tracking

**Cache Structure:**
```
.cve_cache/
├── cve_data_YYYYMMDD.json
├── cvss_scores.db
└── package_vulnerabilities.db
```

**Cache Management:**
```bash
# View cache size
du -sh .cve_cache/

# Clear cache (forces refresh)
rm -rf .cve_cache/

# Cache is automatically recreated on next run
```

### External CVE Databases

The tool can integrate with:

- **NVD** (National Vulnerability Database)
- **Distribution Security Trackers**
- **MITRE CVE Database**
- **Red Hat CVE Database**
- **Ubuntu CVE Tracker**

## Remediation

### Automatic Remediation Scripts

When critical/high CVEs are detected, an automated script is generated:

**Script Name**: `fix_critical_cves_YYYYMMDD_HHMMSS.sh`

**Contents:**

```bash
#!/bin/bash
# Critical CVE Remediation Script
# Generated: 2024-11-09
# System: Ubuntu 22.04

if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

echo "Starting CVE remediation..."

# Fix for CVE-2024-12345 (CVSS: 9.8 - CRITICAL)
echo "Fixing CVE-2024-12345..."
sudo apt-get update && sudo apt-get install --only-upgrade openssl

# Fix for CVE-2024-67890 (CVSS: 8.1 - HIGH)
echo "Fixing CVE-2024-67890..."
sudo apt-get update && sudo apt-get install --only-upgrade nginx

echo "Remediation complete. Please reboot."
```

### Manual Remediation

#### Debian/Ubuntu
```bash
# Update specific package
sudo apt-get update
sudo apt-get install --only-upgrade package-name

# Update all security patches
sudo apt-get update
sudo apt-get upgrade -y
```

#### RHEL/CentOS 7
```bash
# Update specific package
sudo yum update package-name

# Install all security updates
sudo yum update --security
```

#### RHEL 8+ / Rocky / AlmaLinux
```bash
# Update specific package
sudo dnf update package-name

# Install all security updates
sudo dnf update --security
```

#### SUSE/openSUSE
```bash
# Apply specific patch
sudo zypper patch --cve CVE-2024-12345

# Apply all security patches
sudo zypper patch --category security
```

### Verification After Remediation

```bash
# Re-run security audit
sudo ./linux_security_audit.sh

# Check specific CVE is fixed
grep "CVE-2024-12345" security_audit_report_*.txt
```

## CVE Report Format

### Standard CVE Entry

```
[CRITICAL] CVE-2024-12345 | CVSS: 9.8 | Package: openssl
  Description: Remote code execution in OpenSSL
  Fixed Version: 1.1.1f-1ubuntu2.20
  Remediation: sudo apt-get install --only-upgrade openssl
```

### Report Sections

**CVE Summary:**
```
CVE SUMMARY
===========
Critical CVEs (CVSS 9.0-10.0): 2
High CVEs (CVSS 7.0-8.9):      5
Medium CVEs (CVSS 4.0-6.9):    12
Low CVEs (CVSS 0.1-3.9):       8
```

**Detailed CVE List:**
- Sorted by severity (CRITICAL first)
- Includes package name
- Shows CVSS score
- Provides fix version
- Contains remediation command

## Best Practices

### Regular CVE Scanning

```bash
# Weekly automated scan
0 2 * * 0 /path/to/linux_security_audit.sh

# Compare with previous week
diff security_audit_report_week1.txt security_audit_report_week2.txt | grep CVE
```

### Patch Management

1. **Critical CVEs**: Patch within 24 hours
2. **High CVEs**: Patch within 1 week
3. **Medium CVEs**: Patch within 1 month
4. **Low CVEs**: Patch during regular maintenance

### Prioritization

Not all CVEs require immediate action. Consider:

- **Exploitability**: Is it actively exploited?
- **Exposure**: Is the vulnerable service exposed?
- **Impact**: What's the potential damage?
- **Mitigation**: Are there compensating controls?

### CVE Tracking

```bash
# Track CVE over time
echo "$(date),CVE-2024-12345,FOUND" >> cve_tracking.csv

# After remediation
echo "$(date),CVE-2024-12345,FIXED" >> cve_tracking.csv
```

## Limitations

### Known Limitations

1. **Advisory Availability**
   - Depends on distribution security team
   - May lag behind CVE publication
   - Not all CVEs have CVSS scores immediately

2. **Version Detection**
   - Package version string parsing may vary
   - Backported fixes may not be detected correctly
   - Custom compiled packages not tracked

3. **Internet Dependency**
   - CVE detection requires internet access
   - Offline environments may have limited detection
   - Firewall rules may block advisory access

4. **False Positives**
   - Some CVEs may not apply to your configuration
   - Vendor-specific patches may resolve without version change
   - Mitigation may exist without package update

5. **Coverage**
   - Only checks package manager-installed software
   - Manually installed software not scanned
   - Container images not included

### Improving Detection

**Install Distribution Tools:**

```bash
# Ubuntu/Debian
sudo apt-get install debsecan apt-show-versions

# RHEL 7/CentOS 7
sudo yum install yum-plugin-security

# RHEL 8+
sudo dnf install dnf-plugin-security-extras
```

**Keep System Updated:**
```bash
# Update package metadata regularly
sudo apt-get update  # Debian/Ubuntu
sudo yum makecache   # RHEL 7
sudo dnf makecache   # RHEL 8+
```

**Enable Security Repositories:**
Ensure security update repositories are enabled in package manager configuration.

## Advanced Features

### CVE Filtering

Future versions may support:

```bash
# Filter by CVSS score
./linux_security_audit.sh --min-cvss 7.0

# Filter by date
./linux_security_audit.sh --cve-since 2024-01-01

# Export CVE list
./linux_security_audit.sh --export-cves cve_list.json
```

### Integration Points

CVE data can be exported to:

- SIEM systems
- Vulnerability management platforms
- Compliance tracking tools
- Ticketing systems

## References

- **CVE**: https://cve.mitre.org/
- **NVD**: https://nvd.nist.gov/
- **CVSS**: https://www.first.org/cvss/
- **Ubuntu CVE Tracker**: https://ubuntu.com/security/cves
- **Red Hat CVE Database**: https://access.redhat.com/security/security-updates/cve
- **Debian Security**: https://www.debian.org/security/

---

For questions about CVE detection, open a GitHub issue or consult the main documentation.

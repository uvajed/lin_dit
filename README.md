# Linux Security Vulnerability Analyzer

A comprehensive multi-distribution security audit tool with CVE detection and CVSS scoring capabilities.

## Overview

This tool performs deep security analysis of Linux systems, detecting vulnerabilities, CVEs, misconfigurations, and providing automated remediation recommendations.

## Features

- **Multi-Distribution Support**: Ubuntu, Debian, RHEL, CentOS, Rocky Linux, AlmaLinux, Fedora, SUSE, openSUSE
- **CVE Detection**: Automatic detection with CVSS scoring
- **Vulnerability Prioritization**: Severity-based classification (Critical, High, Medium, Low)
- **Automated Remediation**: Generates executable scripts to fix critical/high CVEs
- **Comprehensive Security Audit**:
  - System Information & CVE Status
  - User & Authentication Security
  - Network Security Configuration
  - File System & Permissions Audit
  - Service & Process Analysis
  - Package Management & Vulnerability Detection
  - Kernel Security & CVE Assessment
  - Log & Audit Analysis
  - Firewall & Security Tools Status
  - Compliance & Best Practices Validation

## Requirements

- **Operating System**: Linux (Debian, RHEL, or SUSE-based distributions)
- **Privileges**: Root/sudo access recommended for complete audit
- **Dependencies**: Standard Linux utilities (bash, awk, grep, etc.)

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd lin_dit

# Make the script executable
chmod +x linux_security_audit.sh
```

## Usage

### Basic Usage (with root privileges)
```bash
sudo ./linux_security_audit.sh
```

### Limited Mode (without root)
```bash
./linux_security_audit.sh
```
Note: Some security checks require root privileges and will be skipped in limited mode.

## Output Files

When executed, the tool generates:

1. **Security Audit Report**: `security_audit_report_YYYYMMDD_HHMMSS.txt`
   - Comprehensive findings report
   - CVE analysis with CVSS scores
   - Risk assessment
   - Remediation recommendations

2. **Remediation Script**: `fix_critical_cves_YYYYMMDD_HHMMSS.sh` (if critical/high CVEs found)
   - Automated fix script for critical and high severity CVEs
   - Executable script with distribution-specific commands

3. **CVE Cache**: `.cve_cache/` directory
   - Local cache for CVE data
   - Speeds up subsequent scans

## Example Output

```
================================================================================
  Linux Security Vulnerability Analyzer with CVE Integration v2.0.0
================================================================================

Detected OS: Ubuntu 22.04 (Debian family)
Package Manager: apt

Starting security audit...
Report will be saved to: security_audit_report_20231109_143022.txt
Remediation script: fix_critical_cves_20231109_143022.sh

Phase 1: System Information Gathering...
Phase 2: User and Authentication Security...
...
Phase 11: CVE Analysis and Reporting...

================================================================================
  AUDIT COMPLETE
================================================================================

Security Findings Summary:
  Critical: 2
  High:     5
  Medium:   12
  Low:      8

CVE Summary:
  Critical CVEs (CVSS 9.0-10.0): 1
  High CVEs (CVSS 7.0-8.9):      4
  Medium CVEs (CVSS 4.0-6.9):    7
  Low CVEs (CVSS 0.1-3.9):       3
```

## Security Findings

The tool categorizes findings by severity:

- **CRITICAL** (CVSS 9.0-10.0): Immediate action required
- **HIGH** (CVSS 7.0-8.9): Address within 24 hours
- **MEDIUM** (CVSS 4.0-6.9): Schedule remediation within 1 week
- **LOW** (CVSS 0.1-3.9): Address during regular maintenance

## Remediation

After running the audit:

1. **Review the Report**: Check `security_audit_report_*.txt` for detailed findings
2. **Execute Remediation Script**: If critical/high CVEs are found:
   ```bash
   sudo ./fix_critical_cves_*.sh
   ```
3. **Reboot if Required**: Some updates may require a system reboot
4. **Re-run Audit**: Verify fixes by running the audit again

## Best Practices

- Run security audits regularly (monthly recommended)
- Always review remediation scripts before execution
- Keep systems updated with latest security patches
- Enable automatic security updates where appropriate
- Maintain audit logs for compliance requirements

## Supported Package Managers

- **apt** (Debian, Ubuntu)
- **dnf** (Fedora, RHEL 8+, Rocky Linux, AlmaLinux)
- **yum** (RHEL 7, CentOS 7)
- **zypper** (SUSE, openSUSE)

## Troubleshooting

### Permission Denied Errors
Run the script with sudo:
```bash
sudo ./linux_security_audit.sh
```

### Missing Commands
Install required package management tools:
```bash
# Debian/Ubuntu
sudo apt-get install debsecan

# RHEL/CentOS
sudo yum install yum-plugin-security

# Fedora
sudo dnf install dnf-plugin-security-extras
```

## Contributing

Contributions are welcome! Please submit pull requests or open issues for bugs and feature requests.

## License

Free to use

## Author

Elvis Ibrahimi - Security Audit Team

## Version

2.0.0

## Changelog

### Version 2.0.0
- Multi-distribution support
- CVE detection with CVSS scoring
- Automated remediation script generation
- Comprehensive security audit across 10 domains
- Risk assessment and prioritization

---

**Note**: This tool is designed for security assessment and should be used responsibly. Always test remediation scripts in non-production environments first.

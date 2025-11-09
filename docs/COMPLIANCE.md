# Compliance Guide

Using the Linux Security Vulnerability Analyzer for security compliance and regulatory requirements.

## Table of Contents

- [Overview](#overview)
- [Supported Standards](#supported-standards)
- [CIS Benchmarks](#cis-benchmarks)
- [PCI DSS](#pci-dss)
- [HIPAA](#hipaa)
- [SOC 2](#soc-2)
- [ISO 27001](#iso-27001)
- [Compliance Reporting](#compliance-reporting)
- [Audit Evidence](#audit-evidence)

## Overview

The Linux Security Vulnerability Analyzer helps organizations meet various compliance requirements by:

- Identifying security vulnerabilities
- Documenting system configurations
- Providing remediation guidance
- Generating audit-ready reports
- Tracking security posture over time

## Supported Standards

### Primary Standards

- **CIS Benchmarks** - Security configuration best practices
- **PCI DSS** - Payment Card Industry Data Security Standard
- **HIPAA** - Health Insurance Portability and Accountability Act
- **SOC 2** - Service Organization Control 2
- **ISO 27001** - Information Security Management System
- **NIST Cybersecurity Framework** - Risk management framework
- **GDPR** - General Data Protection Regulation (data security aspects)

### Check Coverage

The tool's 10 audit domains map to compliance requirements:

| Audit Domain | CIS | PCI DSS | HIPAA | SOC 2 | ISO 27001 |
|--------------|-----|---------|-------|-------|-----------|
| System Information | ✓ | ✓ | ✓ | ✓ | ✓ |
| User & Authentication | ✓ | ✓ | ✓ | ✓ | ✓ |
| Network Security | ✓ | ✓ | ✓ | ✓ | ✓ |
| File System & Permissions | ✓ | ✓ | ✓ | ✓ | ✓ |
| Services & Processes | ✓ | ✓ | ✓ | ✓ | ✓ |
| Package Management | ✓ | ✓ | ✓ | ✓ | ✓ |
| Kernel Security | ✓ | ✓ | ✓ | ✓ | ✓ |
| Logs & Auditing | ✓ | ✓ | ✓ | ✓ | ✓ |
| Firewall & Security Tools | ✓ | ✓ | ✓ | ✓ | ✓ |
| Compliance & Best Practices | ✓ | ✓ | ✓ | ✓ | ✓ |

## CIS Benchmarks

### Overview

CIS (Center for Internet Security) Benchmarks provide configuration guidelines for secure systems.

### Relevant CIS Controls

The audit tool addresses these CIS Benchmark sections:

**1. Initial Setup**
- Filesystem configuration
- Partition mounting
- Boot loader security

**2. Services**
- Service configuration
- Service clients
- Special purpose services

**3. Network Configuration**
- Network parameters
- Firewall configuration
- Wireless networking

**4. Logging and Auditing**
- System logging
- Audit daemon configuration
- Log monitoring

**5. Access, Authentication and Authorization**
- PAM configuration
- User accounts and environment
- Sudo configuration
- SSH configuration

**6. System Maintenance**
- System file permissions
- User and group settings
- Software updates

### CIS Benchmark Mapping

#### Access Control (CIS 5.x)

**Tool Checks:**
- ✓ Root account detection (5.1)
- ✓ Empty password detection (5.2)
- ✓ Sudo configuration review (5.3)
- ✓ SSH configuration hardening (5.4)

**Example Finding:**
```
[HIGH] SSH PermitRootLogin Enabled
Description: SSH allows direct root login (CIS 5.4.10)
Remediation: Set 'PermitRootLogin no' in /etc/ssh/sshd_config
```

#### Logging and Auditing (CIS 4.x)

**Tool Checks:**
- ✓ Auditd installation (4.1)
- ✓ Log file permissions (4.2)
- ✓ Logging configuration (4.3)

**Example Finding:**
```
[MEDIUM] Audit Daemon Not Running
Description: auditd is not active (CIS 4.1.2)
Remediation: systemctl enable --now auditd
```

#### Network Configuration (CIS 3.x)

**Tool Checks:**
- ✓ Firewall status (3.1)
- ✓ Open ports review (3.2)
- ✓ Network parameters (3.3)

**Example Finding:**
```
[HIGH] Firewall Disabled
Description: UFW/firewalld not active (CIS 3.1.1)
Remediation: systemctl enable --now firewalld
```

### CIS Compliance Reporting

Generate CIS-focused reports:

```bash
# Run audit
sudo ./linux_security_audit.sh

# Extract CIS-relevant findings
grep -E "CIS|authentication|firewall|audit|SSH" security_audit_report_*.txt > cis_findings.txt
```

## PCI DSS

### Overview

PCI DSS (Payment Card Industry Data Security Standard) applies to organizations handling credit card data.

### Relevant PCI DSS Requirements

#### Requirement 2: Secure Configurations

**Tool Support:**
- Configuration documentation
- Default credential detection
- Service hardening verification

**Example Compliance:**
```
[CRITICAL] Default Password Detected
PCI DSS 2.1: Change vendor-supplied defaults
Finding: System using default credentials
Action: Change all default passwords immediately
```

#### Requirement 6: Secure Development

**Tool Support:**
- Vulnerability scanning (CVE detection)
- Patch management verification
- Security update tracking

**Example Compliance:**
```
PCI DSS 6.2: Protect systems against known vulnerabilities
CVEs Detected: 15 (3 Critical, 5 High, 7 Medium)
Action: Apply security patches within compliance timelines
```

#### Requirement 8: Access Control

**Tool Support:**
- User account auditing
- Authentication mechanism review
- Privilege management

**Example Compliance:**
```
PCI DSS 8.1: Unique user identification
Finding: 2 accounts with UID 0 (root equivalent)
Action: Ensure each user has unique credentials
```

#### Requirement 10: Logging and Monitoring

**Tool Support:**
- Audit log verification
- Log retention checking
- Logging coverage assessment

**Example Compliance:**
```
PCI DSS 10.2: Implement automated audit trails
Finding: Auditd not configured
Action: Enable and configure audit logging
```

### PCI DSS Compliance Workflow

1. **Run Quarterly Scans** (PCI DSS 11.2.2)
   ```bash
   # Schedule quarterly
   0 2 1 */3 * /path/to/linux_security_audit.sh
   ```

2. **Document Findings**
   - Save all reports
   - Track remediation
   - Maintain evidence

3. **Remediate Vulnerabilities**
   - Critical: Within 24 hours
   - High: Within 30 days
   - Medium: Within 90 days

4. **Verify Remediation**
   ```bash
   # Re-scan after fixes
   sudo ./linux_security_audit.sh
   ```

## HIPAA

### Overview

HIPAA (Health Insurance Portability and Accountability Act) requires protection of Protected Health Information (PHI).

### HIPAA Security Rule Alignment

#### Administrative Safeguards

**§164.308(a)(1) - Security Management Process**

Tool Support:
- Risk assessment through vulnerability scanning
- Security incident identification
- Documentation of security posture

**§164.308(a)(5) - Security Awareness and Training**

Tool Support:
- Security configuration documentation
- Best practice recommendations
- Training materials

#### Physical Safeguards

**§164.310(d) - Device and Media Controls**

Tool Support:
- File system encryption verification
- Access control validation
- Audit trail verification

#### Technical Safeguards

**§164.312(a)(1) - Access Control**

Tool Support:
- User authentication review
- Access control verification
- Unique user identification

**§164.312(b) - Audit Controls**

Tool Support:
- Audit log verification
- Logging coverage assessment
- Access tracking

**§164.312(c)(1) - Integrity**

Tool Support:
- File integrity verification
- Change detection
- System integrity checks

**§164.312(e)(1) - Transmission Security**

Tool Support:
- Network security configuration
- Encryption verification
- Secure communication protocols

### HIPAA Compliance Reporting

```bash
# Generate HIPAA-focused report
sudo ./linux_security_audit.sh

# Extract relevant sections
grep -E "authentication|encryption|audit|access|log" security_audit_report_*.txt > hipaa_controls.txt
```

### Evidence Collection

Maintain for HIPAA audits:

1. **Monthly Audit Reports**
   - System security scans
   - Vulnerability assessments
   - Remediation tracking

2. **Access Control Documentation**
   - User account reviews
   - Permission audits
   - Authentication mechanisms

3. **Audit Trail Evidence**
   - Logging configuration
   - Log retention
   - Access tracking

## SOC 2

### Overview

SOC 2 (Service Organization Control 2) evaluates controls relevant to security, availability, processing integrity, confidentiality, and privacy.

### SOC 2 Trust Service Criteria

#### CC6.1 - Logical Access Controls

Tool Support:
- User account management review
- Authentication mechanism verification
- Privileged access monitoring

**Evidence:**
```
User & Authentication Security Check Results:
- Root users: 1 (compliant)
- Empty passwords: 0 (compliant)
- Sudo configuration: Reviewed
- Failed login attempts: Monitored
```

#### CC6.6 - Logical Access - Removal

Tool Support:
- Inactive account detection
- Account review documentation

#### CC7.1 - Detection of Security Events

Tool Support:
- Security event logging verification
- Log monitoring configuration
- Intrusion detection status

**Evidence:**
```
Logs & Auditing Check Results:
- Auditd status: Running (compliant)
- Log retention: 90 days (compliant)
- Log monitoring: fail2ban active (compliant)
```

#### CC7.2 - Monitoring of Security Events

Tool Support:
- Continuous monitoring verification
- Alert configuration review
- Security tool status

#### CC8.1 - Vulnerability Management

Tool Support:
- CVE detection and scoring
- Patch management verification
- Vulnerability remediation tracking

**Evidence:**
```
CVE SUMMARY:
Critical CVEs: 0 (compliant)
High CVEs: 2 (remediation in progress)
Patch Timeline: Within SLA
```

### SOC 2 Audit Preparation

1. **Monthly Evidence Collection**
   ```bash
   # Run monthly audit
   sudo ./linux_security_audit.sh

   # Archive with date
   mv security_audit_report_*.txt /audit/evidence/$(date +%Y-%m)/
   ```

2. **Quarterly Control Testing**
   ```bash
   # Test security controls
   sudo ./linux_security_audit.sh

   # Document results
   echo "$(date): Quarterly control test completed" >> control_testing_log.txt
   ```

3. **Annual Review**
   - Compare year-over-year trends
   - Document improvements
   - Update policies

## ISO 27001

### Overview

ISO 27001 is an international standard for information security management systems (ISMS).

### ISO 27001 Annex A Controls

#### A.9 - Access Control

**A.9.1 - Business requirements for access control**

Tool Support:
- Access control policy verification
- User access review
- Privileged access management

**A.9.2 - User access management**

Tool Support:
- User registration review
- Access provisioning validation
- Access rights review

**A.9.4 - System and application access control**

Tool Support:
- Secure logon procedures
- Password management systems
- Use of privileged utilities

#### A.12 - Operations Security

**A.12.2 - Protection from malware**

Tool Support:
- Antivirus status verification
- Malware protection review

**A.12.4 - Logging and monitoring**

Tool Support:
- Event logging verification
- Log protection
- Administrator and operator logs

**A.12.6 - Technical vulnerability management**

Tool Support:
- Vulnerability identification (CVE)
- Vulnerability assessment
- Remediation tracking

#### A.13 - Communications Security

**A.13.1 - Network security management**

Tool Support:
- Network controls verification
- Network segregation review
- Security of network services

#### A.14 - System Acquisition, Development and Maintenance

**A.14.2 - Security in development and support processes**

Tool Support:
- Secure development policy verification
- System change control procedures

### ISO 27001 Compliance Documentation

```bash
# Generate monthly evidence
sudo ./linux_security_audit.sh

# Create compliance summary
cat > iso27001_summary.txt << EOF
ISO 27001 Compliance Evidence
Date: $(date)
System: $(hostname)

A.9 Access Control: $(grep -c "User" security_audit_report_*.txt) checks performed
A.12 Operations Security: $(grep -c "Service\|Process" security_audit_report_*.txt) checks performed
A.12.6 Vulnerability Management: $(grep "Total CVEs" security_audit_report_*.txt)
A.13 Communications Security: $(grep -c "Network" security_audit_report_*.txt) checks performed

Full report: security_audit_report_*.txt
EOF
```

## Compliance Reporting

### Report Structure for Compliance

```
================================================================================
  COMPLIANCE AUDIT REPORT
================================================================================

Standard: [PCI DSS / HIPAA / SOC 2 / ISO 27001]
Audit Date: YYYY-MM-DD
System: hostname
Auditor: [Name/Tool]

EXECUTIVE SUMMARY
=================
Controls Tested: XX
Controls Passed: XX
Controls Failed: XX
Exceptions: XX

DETAILED FINDINGS
=================
[Control ID] [Control Description]
Status: [PASS/FAIL/EXCEPTION]
Evidence: [Finding details]
Remediation: [Required actions]

REMEDIATION PLAN
================
Priority 1 (Critical): X items
Priority 2 (High): X items
Priority 3 (Medium): X items

APPENDIX
========
[Full security audit report]
```

### Automated Compliance Reporting

```bash
#!/bin/bash
# Generate compliance report

STANDARD="PCI-DSS"  # Or HIPAA, SOC2, ISO27001
DATE=$(date +%Y-%m-%d)

# Run audit
sudo ./linux_security_audit.sh

# Create compliance summary
cat > compliance_report_${STANDARD}_${DATE}.txt << EOF
COMPLIANCE AUDIT REPORT
Standard: ${STANDARD}
Date: ${DATE}
System: $(hostname)

SUMMARY:
Critical Findings: $(grep -c "\[CRITICAL\]" security_audit_report_*.txt)
High Findings: $(grep -c "\[HIGH\]" security_audit_report_*.txt)
Medium Findings: $(grep -c "\[MEDIUM\]" security_audit_report_*.txt)

CVE Status:
Critical CVEs: $(grep "Critical CVEs" security_audit_report_*.txt | awk '{print $NF}')
High CVEs: $(grep "High CVEs" security_audit_report_*.txt | awk '{print $NF}')

Compliance Status: $([[ $(grep -c "\[CRITICAL\]" security_audit_report_*.txt) -eq 0 ]] && echo "PASS" || echo "FAIL")

Full report attached: security_audit_report_*.txt
EOF

echo "Compliance report generated: compliance_report_${STANDARD}_${DATE}.txt"
```

## Audit Evidence

### Evidence Collection

Maintain audit evidence for compliance:

1. **Security Scan Reports**
   ```bash
   # Monthly scans
   /audit/evidence/2024/01/security_audit_report_20240115.txt
   /audit/evidence/2024/02/security_audit_report_20240215.txt
   ```

2. **Remediation Documentation**
   ```bash
   # Track fixes
   /audit/remediation/2024/01/fix_critical_cves_20240115.sh
   /audit/remediation/2024/01/remediation_log.txt
   ```

3. **Trending Reports**
   ```bash
   # Year-over-year comparison
   /audit/trends/security_trends_2024.pdf
   ```

### Evidence Retention

Compliance requirements for evidence retention:

- **PCI DSS**: 1 year minimum
- **HIPAA**: 6 years
- **SOC 2**: 1 year minimum
- **ISO 27001**: Per organizational policy (typically 3 years)

### Audit Trail

Maintain audit trails:

```bash
# Log all audit runs
echo "$(date),$(whoami),security_audit_run,$(hostname)" >> /var/log/audit_trail.log

# Track report generation
ls -l security_audit_report_*.txt >> /var/log/report_inventory.log
```

## Best Practices for Compliance

1. **Regular Scanning**
   - Monthly minimum
   - After significant changes
   - Before audits

2. **Evidence Preservation**
   - Secure storage
   - Encrypted backups
   - Access controls

3. **Remediation Tracking**
   - Document all fixes
   - Track timelines
   - Verify completion

4. **Change Management**
   - Scan before/after changes
   - Document impacts
   - Review security posture

5. **Continuous Improvement**
   - Trend analysis
   - Process refinement
   - Tool updates

## Additional Resources

- **CIS Benchmarks**: https://www.cisecurity.org/cis-benchmarks/
- **PCI DSS**: https://www.pcisecuritystandards.org/
- **HIPAA**: https://www.hhs.gov/hipaa/
- **SOC 2**: https://www.aicpa.org/
- **ISO 27001**: https://www.iso.org/isoiec-27001-information-security.html

---

For compliance-specific questions, consult your legal/compliance team and security professionals.

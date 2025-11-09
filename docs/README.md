# Documentation

Comprehensive documentation for the Linux Security Vulnerability Analyzer.

## Documentation Files

### [USAGE.md](USAGE.md)
Complete usage guide covering:
- Basic and advanced usage
- Running audits
- Understanding reports
- Interpreting findings
- Using remediation scripts
- Best practices
- Common scenarios

**Read this first** to learn how to use the tool effectively.

### [CVE_DETECTION.md](CVE_DETECTION.md)
CVE detection and CVSS scoring guide:
- CVE detection methods
- CVSS scoring system
- Distribution-specific detection
- CVE database management
- Remediation strategies
- Limitations and workarounds

**Essential reading** for understanding vulnerability detection.

### [COMPLIANCE.md](COMPLIANCE.md)
Compliance and regulatory requirements:
- CIS Benchmarks alignment
- PCI DSS requirements
- HIPAA compliance
- SOC 2 controls
- ISO 27001 standards
- Compliance reporting
- Audit evidence collection

**Important** for organizations with compliance requirements.

## Quick Links

### Getting Started
- [Installation Guide](../INSTALL.md)
- [Quick Start](../README.md#usage)
- [First Audit](USAGE.md#running-the-audit)

### Understanding Output
- [Report Structure](USAGE.md#understanding-the-report)
- [Severity Levels](USAGE.md#severity-levels)
- [CVE Format](CVE_DETECTION.md#cve-report-format)
- [Sample Reports](../examples/)

### Taking Action
- [Interpreting Findings](USAGE.md#interpreting-findings)
- [Using Remediation Scripts](USAGE.md#using-remediation-scripts)
- [Best Practices](USAGE.md#best-practices)
- [Troubleshooting](../INSTALL.md#troubleshooting)

### Advanced Topics
- [CVE Detection Methods](CVE_DETECTION.md#detection-process)
- [CVSS Scoring](CVE_DETECTION.md#cvss-scoring)
- [Automated Audits](USAGE.md#automated-audits)
- [SIEM Integration](USAGE.md#integration-with-siem)

### Compliance
- [CIS Benchmarks](COMPLIANCE.md#cis-benchmarks)
- [PCI DSS](COMPLIANCE.md#pci-dss)
- [HIPAA](COMPLIANCE.md#hipaa)
- [SOC 2](COMPLIANCE.md#soc-2)
- [ISO 27001](COMPLIANCE.md#iso-27001)

### Contributing
- [Contributing Guide](../CONTRIBUTING.md)
- [Security Policy](../SECURITY.md)
- [Changelog](../CHANGELOG.md)

## Documentation by Role

### Security Administrators
**Recommended reading order:**
1. [USAGE.md](USAGE.md) - How to run audits
2. [CVE_DETECTION.md](CVE_DETECTION.md) - Understanding vulnerabilities
3. [COMPLIANCE.md](COMPLIANCE.md) - Meeting compliance requirements

### System Administrators
**Recommended reading order:**
1. [Installation Guide](../INSTALL.md) - Setting up the tool
2. [USAGE.md](USAGE.md) - Running and understanding audits
3. [Best Practices](USAGE.md#best-practices) - Operational guidance

### Compliance Officers
**Recommended reading order:**
1. [COMPLIANCE.md](COMPLIANCE.md) - Compliance mapping
2. [CVE_DETECTION.md](CVE_DETECTION.md) - Vulnerability management
3. [Audit Evidence](COMPLIANCE.md#audit-evidence) - Evidence collection

### Developers
**Recommended reading order:**
1. [Contributing Guide](../CONTRIBUTING.md) - Development setup
2. [Security Policy](../SECURITY.md) - Security considerations
3. [USAGE.md](USAGE.md) - Tool functionality

## Documentation Structure

```
docs/
├── README.md              # This file - documentation index
├── USAGE.md              # Complete usage guide
├── CVE_DETECTION.md      # CVE detection and CVSS guide
└── COMPLIANCE.md         # Compliance and regulations guide

../
├── README.md             # Main project documentation
├── INSTALL.md            # Installation instructions
├── CONTRIBUTING.md       # Contribution guidelines
├── SECURITY.md           # Security policy
├── CHANGELOG.md          # Version history
└── examples/             # Sample outputs
    ├── README.md
    ├── sample_report.txt
    └── sample_remediation_script.sh
```

## Common Tasks

### First Time Setup
```bash
# 1. Install
git clone https://github.com/uvajed/lin_dit.git
cd lin_dit
chmod +x linux_security_audit.sh

# 2. Read basics
cat README.md

# 3. Run first audit
sudo ./linux_security_audit.sh

# 4. Review report
less security_audit_report_*.txt
```

**Documentation**: [INSTALL.md](../INSTALL.md), [USAGE.md](USAGE.md)

### Understanding CVEs
```bash
# 1. Run audit
sudo ./linux_security_audit.sh

# 2. Check CVE summary
grep "CVE SUMMARY" security_audit_report_*.txt -A 5

# 3. Review critical CVEs
grep "\[CRITICAL\].*CVE" security_audit_report_*.txt
```

**Documentation**: [CVE_DETECTION.md](CVE_DETECTION.md)

### Compliance Reporting
```bash
# 1. Run audit
sudo ./linux_security_audit.sh

# 2. Generate compliance report
# See COMPLIANCE.md for examples

# 3. Collect evidence
mkdir -p /audit/evidence/$(date +%Y-%m)
cp security_audit_report_*.txt /audit/evidence/$(date +%Y-%m)/
```

**Documentation**: [COMPLIANCE.md](COMPLIANCE.md)

### Remediation
```bash
# 1. Review findings
less security_audit_report_*.txt

# 2. Review remediation script
cat fix_critical_cves_*.sh

# 3. Create backup
# (your backup method)

# 4. Run remediation
sudo ./fix_critical_cves_*.sh

# 5. Verify
sudo ./linux_security_audit.sh
```

**Documentation**: [USAGE.md](USAGE.md#using-remediation-scripts)

## Frequently Asked Questions

### General Questions

**Q: How often should I run audits?**
A: Monthly minimum, weekly recommended. See [Best Practices](USAGE.md#best-practices).

**Q: Do I need root privileges?**
A: Root is recommended for complete audits. Limited mode available without root. See [USAGE.md](USAGE.md#basic-usage).

**Q: How long does an audit take?**
A: Typically 2-5 minutes depending on system size and configuration.

**Q: Can I run this on production systems?**
A: Yes, the audit is read-only and safe. Always test first though.

### CVE Questions

**Q: How accurate is CVE detection?**
A: Depends on distribution's security advisories. See [CVE Detection Accuracy](CVE_DETECTION.md#detection-accuracy).

**Q: What do CVSS scores mean?**
A: See [CVSS Scoring](CVE_DETECTION.md#cvss-scoring) for detailed explanation.

**Q: Should I patch all CVEs immediately?**
A: Prioritize by severity. See [Remediation Timeline](USAGE.md#severity-levels).

### Compliance Questions

**Q: Does this meet PCI DSS requirements?**
A: It helps with vulnerability scanning (Req 6.2, 11.2). See [PCI DSS](COMPLIANCE.md#pci-dss).

**Q: Is this sufficient for HIPAA compliance?**
A: It's one component of HIPAA compliance. See [HIPAA](COMPLIANCE.md#hipaa).

**Q: How do I use this for SOC 2 audits?**
A: See [SOC 2 Audit Preparation](COMPLIANCE.md#soc-2-audit-preparation).

## Additional Resources

### External Documentation
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [CVE Database](https://cve.mitre.org/)
- [NVD](https://nvd.nist.gov/)
- [CVSS Guide](https://www.first.org/cvss/)

### Community
- [GitHub Issues](https://github.com/uvajed/lin_dit/issues) - Bug reports and feature requests
- [GitHub Discussions](https://github.com/uvajed/lin_dit/discussions) - Community discussions

### Support
For issues or questions:
1. Check documentation first
2. Review [examples](../examples/)
3. Search [existing issues](https://github.com/uvajed/lin_dit/issues)
4. Open new issue if needed

## Contributing to Documentation

Found an error or want to improve documentation?

1. Read [Contributing Guide](../CONTRIBUTING.md)
2. Fork repository
3. Make improvements
4. Submit pull request

Documentation improvements are always welcome!

## Changelog

See [CHANGELOG.md](../CHANGELOG.md) for version history and changes.

## License

See [LICENSE](../LICENSE) for license information.

---

**Last Updated**: 2024-11-09
**Version**: 2.0.0

For the latest documentation, visit: https://github.com/uvajed/lin_dit

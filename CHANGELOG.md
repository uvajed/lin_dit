# Changelog

All notable changes to the Linux Security Vulnerability Analyzer will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2024-11-09

### Added
- **Multi-Distribution Support**: Full support for Debian, Ubuntu, RHEL, CentOS, Rocky Linux, AlmaLinux, Fedora, SUSE, and openSUSE
- **CVE Integration**: Comprehensive CVE detection with CVSS scoring
- **Automated Remediation**: Auto-generated remediation scripts for critical and high severity CVEs
- **Enhanced OS Detection**: Improved operating system and distribution detection
- **Package Manager Support**: Support for apt, dnf, yum, zypper, and rpm
- **CVE Caching**: Local caching mechanism for CVE data to improve performance
- **Security Audit Domains**:
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
- **Severity Classification**: CRITICAL, HIGH, MEDIUM, LOW categorization
- **Executive Summary**: Comprehensive summary with risk assessment
- **CVE Report Section**: Dedicated CVE analysis and reporting
- **Remediation Script Generation**: Automatic creation of executable fix scripts
- **Privilege Detection**: Support for both root and non-root execution modes
- **Safe Execution**: Uses `set -euo pipefail` for error handling
- **Temporary File Management**: Secure creation and cleanup of temporary files
- **Detailed Logging**: Comprehensive logging to report files

### Changed
- **Report Format**: Enhanced report structure with better organization
- **Output Files**: Timestamped output files for better tracking
- **Error Handling**: Improved error handling and user feedback
- **Code Structure**: Modularized code with clear function separation

### Security
- **Input Validation**: Enhanced input validation throughout
- **Secure Temp Files**: Using `mktemp` for secure temporary file creation
- **Automatic Cleanup**: Trap-based cleanup of temporary files
- **Privilege Separation**: Clear separation of privileged and non-privileged operations

### Documentation
- **README.md**: Comprehensive documentation with usage examples
- **CONTRIBUTING.md**: Contribution guidelines for developers
- **SECURITY.md**: Security policy and vulnerability reporting
- **INSTALL.md**: Detailed installation instructions
- **LICENSE**: MIT License
- **.gitignore**: Proper exclusion of generated files

## [1.0.0] - [Previous Release]

### Initial Release
- Basic security audit functionality
- Single distribution support
- Basic vulnerability detection
- Simple report generation

---

## Release Notes

### Version 2.0.0 Highlights

This major release represents a complete overhaul of the Linux Security Vulnerability Analyzer with focus on:

#### Enterprise-Ready Features
- **Multi-Distribution**: Works across all major Linux distributions
- **CVE Integration**: Real-time CVE detection and scoring
- **Automation**: Auto-remediation script generation
- **Scalability**: Designed for use in enterprise environments

#### Improved Security Checks
- Expanded from basic checks to 10 comprehensive security domains
- CVE detection with CVSS scoring
- Enhanced firewall and network security analysis
- Compliance checking against industry standards

#### Better User Experience
- Clear severity classification
- Executive summary with actionable recommendations
- Timestamped reports for tracking over time
- Support for both privileged and limited execution

#### Developer Improvements
- Modular code structure
- Comprehensive error handling
- Extensive documentation
- Contribution guidelines

### Upgrade Notes

When upgrading from 1.x to 2.0:

1. **Backup**: Backup existing reports and scripts
2. **Review Changes**: Check CHANGELOG for breaking changes
3. **Test**: Test in non-production environment first
4. **Update Scripts**: Update any automation using the tool
5. **Review Output**: New report format may require parser updates

### Breaking Changes

- Report format has changed significantly
- Output file naming convention updated
- Some command-line options may have changed
- CVE detection requires internet connectivity for best results

### Known Issues

- CVE detection accuracy depends on distribution's security advisory databases
- Some checks require root privileges to complete
- CVSS scores may be approximated for some CVEs pending database updates

### Deprecation Notices

- Legacy report format is no longer supported
- Single-distribution mode removed (now auto-detects)

---

## Versioning

We use [SemVer](http://semver.org/) for versioning:

- **MAJOR**: Incompatible API changes
- **MINOR**: New features (backwards-compatible)
- **PATCH**: Bug fixes (backwards-compatible)

## Support

- **Version 2.0.x**: Actively supported with security updates
- **Version 1.x**: No longer supported

---

For more information about releases, see the [GitHub Releases](https://github.com/uvajed/lin_dit/releases) page.

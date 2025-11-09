# Installation Guide

Complete installation instructions for the Linux Security Vulnerability Analyzer.

## Table of Contents

- [System Requirements](#system-requirements)
- [Quick Installation](#quick-installation)
- [Distribution-Specific Installation](#distribution-specific-installation)
- [Optional Dependencies](#optional-dependencies)
- [Post-Installation Setup](#post-installation-setup)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)
- [Uninstallation](#uninstallation)

## System Requirements

### Supported Operating Systems

- **Debian-based**: Ubuntu 18.04+, Debian 9+, Linux Mint, Pop!_OS, Elementary OS
- **RHEL-based**: RHEL 7+, CentOS 7+, Rocky Linux 8+, AlmaLinux 8+, Oracle Linux 7+
- **Fedora**: Fedora 30+
- **SUSE-based**: SUSE Linux Enterprise 12+, openSUSE Leap 15+

### Minimum Requirements

- **Bash**: Version 4.0 or higher
- **Disk Space**: 10 MB for script and dependencies, 50 MB for CVE cache
- **Memory**: 256 MB RAM (recommended: 512 MB)
- **Privileges**: Some checks require root/sudo access

### Required Utilities

The following utilities are required (usually pre-installed):

- `bash` (version 4.0+)
- `awk`
- `grep`
- `sed`
- `curl` or `wget` (for CVE data fetching)
- `date`
- `hostname`
- `uname`

## Quick Installation

### Method 1: Clone from Git (Recommended)

```bash
# Clone the repository
git clone https://github.com/uvajed/lin_dit.git

# Navigate to directory
cd lin_dit

# Make script executable
chmod +x linux_security_audit.sh

# Run the audit
sudo ./linux_security_audit.sh
```

### Method 2: Download Script Directly

```bash
# Download the script
wget https://raw.githubusercontent.com/uvajed/lin_dit/main/linux_security_audit.sh

# Make it executable
chmod +x linux_security_audit.sh

# Run the audit
sudo ./linux_security_audit.sh
```

### Method 3: curl

```bash
# Download and make executable
curl -o linux_security_audit.sh https://raw.githubusercontent.com/uvajed/lin_dit/main/linux_security_audit.sh
chmod +x linux_security_audit.sh

# Run the audit
sudo ./linux_security_audit.sh
```

## Distribution-Specific Installation

### Ubuntu / Debian

```bash
# Update package lists
sudo apt-get update

# Install git (if not already installed)
sudo apt-get install -y git

# Clone repository
git clone https://github.com/uvajed/lin_dit.git
cd lin_dit

# Make executable
chmod +x linux_security_audit.sh

# Install optional dependencies for enhanced CVE detection
sudo apt-get install -y debsecan

# Run the audit
sudo ./linux_security_audit.sh
```

### RHEL / CentOS / Rocky Linux / AlmaLinux

```bash
# Install git (if not already installed)
sudo yum install -y git

# For RHEL 8+ / Rocky / AlmaLinux (use dnf)
sudo dnf install -y git

# Clone repository
git clone https://github.com/uvajed/lin_dit.git
cd lin_dit

# Make executable
chmod +x linux_security_audit.sh

# Install optional dependencies
sudo yum install -y yum-plugin-security  # RHEL 7/CentOS 7
# OR
sudo dnf install -y dnf-plugin-security-extras  # RHEL 8+

# Run the audit
sudo ./linux_security_audit.sh
```

### Fedora

```bash
# Install git
sudo dnf install -y git

# Clone repository
git clone https://github.com/uvajed/lin_dit.git
cd lin_dit

# Make executable
chmod +x linux_security_audit.sh

# Run the audit
sudo ./linux_security_audit.sh
```

### SUSE / openSUSE

```bash
# Install git
sudo zypper install -y git

# Clone repository
git clone https://github.com/uvajed/lin_dit.git
cd lin_dit

# Make executable
chmod +x linux_security_audit.sh

# Run the audit
sudo ./linux_security_audit.sh
```

## Optional Dependencies

While the script works with standard utilities, these optional packages enhance functionality:

### For Enhanced CVE Detection

**Debian/Ubuntu:**
```bash
sudo apt-get install -y debsecan apt-show-versions
```

**RHEL 7/CentOS 7:**
```bash
sudo yum install -y yum-plugin-security yum-utils
```

**RHEL 8+/Rocky/AlmaLinux:**
```bash
sudo dnf install -y dnf-plugins-core
```

**Fedora:**
```bash
sudo dnf install -y dnf-plugins-core
```

**SUSE/openSUSE:**
```bash
sudo zypper install -y zypper-aptitude
```

### For Code Validation (Development)

```bash
# Install ShellCheck for script validation
# Ubuntu/Debian
sudo apt-get install -y shellcheck

# RHEL/CentOS/Fedora
sudo dnf install -y ShellCheck

# SUSE
sudo zypper install -y ShellCheck
```

## Post-Installation Setup

### 1. Verify Installation

```bash
# Check Bash version (should be 4.0+)
bash --version

# Verify script syntax
bash -n linux_security_audit.sh

# Test script execution
./linux_security_audit.sh --help 2>/dev/null || echo "Script is ready to run"
```

### 2. Set Up Directory Structure

```bash
# Create a dedicated directory for security audits
sudo mkdir -p /var/security/audits
sudo chmod 750 /var/security/audits

# Move script to dedicated location (optional)
sudo cp linux_security_audit.sh /var/security/
sudo chmod 750 /var/security/linux_security_audit.sh
```

### 3. Configure Automated Audits (Optional)

Set up cron job for regular audits:

```bash
# Edit crontab
sudo crontab -e

# Add weekly audit (runs every Sunday at 2 AM)
0 2 * * 0 /path/to/linux_security_audit.sh

# Or monthly audit (runs on 1st of month at 2 AM)
0 2 1 * * /path/to/linux_security_audit.sh
```

### 4. Set Up Log Rotation

Create log rotation configuration:

```bash
# Create logrotate configuration
sudo tee /etc/logrotate.d/security_audit << EOF
/path/to/security_audit_report_*.txt {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
}
EOF
```

## Installation in Containers

### Docker

```bash
# Create Dockerfile
cat > Dockerfile << 'EOF'
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y \
    bash \
    git \
    debsecan \
    && rm -rf /var/lib/apt/lists/*
COPY linux_security_audit.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/linux_security_audit.sh
CMD ["/usr/local/bin/linux_security_audit.sh"]
EOF

# Build image
docker build -t linux-security-audit .

# Run audit
docker run --rm -v $(pwd):/output linux-security-audit
```

### Podman

```bash
# Run audit with Podman
podman run --rm -v $(pwd):/output ubuntu:22.04 bash -c "
    apt-get update && apt-get install -y git && \
    git clone https://github.com/uvajed/lin_dit.git && \
    cd lin_dit && \
    chmod +x linux_security_audit.sh && \
    ./linux_security_audit.sh
"
```

## Verification

### Verify Installation

```bash
# 1. Check script is executable
ls -l linux_security_audit.sh

# Expected output: -rwxr-xr-x ... linux_security_audit.sh

# 2. Run syntax check
bash -n linux_security_audit.sh
# No output = success

# 3. Test dry run (without root)
./linux_security_audit.sh
# Should prompt for limited mode or root privileges

# 4. Verify version
grep "SCRIPT_VERSION" linux_security_audit.sh
# Should show: readonly SCRIPT_VERSION="2.0.0"
```

### Test Run

```bash
# Run full audit with root privileges
sudo ./linux_security_audit.sh

# Check outputs were generated
ls -l security_audit_report_*.txt
ls -l fix_critical_cves_*.sh 2>/dev/null || echo "No critical CVEs found"
```

## Troubleshooting

### Permission Denied

```bash
# Make script executable
chmod +x linux_security_audit.sh

# Run with sudo for full audit
sudo ./linux_security_audit.sh
```

### Bash Version Too Old

```bash
# Check Bash version
bash --version

# Update Bash (Ubuntu/Debian)
sudo apt-get update && sudo apt-get upgrade bash

# Update Bash (RHEL/CentOS)
sudo yum update bash
```

### Missing Dependencies

```bash
# Install missing utilities (example for Ubuntu)
sudo apt-get install -y coreutils grep gawk sed curl

# For RHEL/CentOS
sudo yum install -y coreutils grep gawk sed curl
```

### CVE Detection Not Working

```bash
# Install distribution-specific CVE tools
# Ubuntu/Debian
sudo apt-get install debsecan

# RHEL/CentOS 7
sudo yum install yum-plugin-security

# RHEL 8+
sudo dnf install dnf-plugin-security-extras

# Verify internet connectivity
ping -c 3 security.ubuntu.com  # Ubuntu
ping -c 3 cdn.redhat.com       # RHEL
```

### Script Fails Immediately

```bash
# Check for syntax errors
bash -n linux_security_audit.sh

# Run with debugging
bash -x linux_security_audit.sh

# Check system logs
sudo journalctl -xe
```

## Uninstallation

### Remove Script and Generated Files

```bash
# Navigate to installation directory
cd /path/to/lin_dit

# Remove generated files
rm -f security_audit_report_*.txt
rm -f fix_critical_cves_*.sh
rm -rf .cve_cache

# Remove script
rm -f linux_security_audit.sh

# Remove directory (if cloned from git)
cd ..
rm -rf lin_dit
```

### Remove Cron Jobs

```bash
# Edit crontab
sudo crontab -e

# Remove the audit cron job lines
# Save and exit
```

### Remove Logrotate Configuration

```bash
sudo rm -f /etc/logrotate.d/security_audit
```

## Upgrade Instructions

### Upgrading from Previous Version

```bash
# Navigate to installation directory
cd lin_dit

# Backup current version
cp linux_security_audit.sh linux_security_audit.sh.backup

# Pull latest changes
git pull origin main

# Or download latest version
wget -O linux_security_audit.sh https://raw.githubusercontent.com/uvajed/lin_dit/main/linux_security_audit.sh

# Make executable
chmod +x linux_security_audit.sh

# Verify upgrade
grep "SCRIPT_VERSION" linux_security_audit.sh

# Test new version
sudo ./linux_security_audit.sh
```

## Next Steps

After installation:

1. **Read Documentation**: Review README.md for usage instructions
2. **Run First Audit**: Execute `sudo ./linux_security_audit.sh`
3. **Review Report**: Check the generated security_audit_report_*.txt
4. **Address Findings**: Review and remediate identified issues
5. **Schedule Regular Audits**: Set up automated periodic scans
6. **Stay Updated**: Check for updates regularly

## Support

If you encounter issues during installation:

- Check [Troubleshooting](#troubleshooting) section
- Review [GitHub Issues](https://github.com/uvajed/lin_dit/issues)
- Consult documentation in `docs/` directory
- Open a new issue if problem persists

---

For more information, see [README.md](README.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

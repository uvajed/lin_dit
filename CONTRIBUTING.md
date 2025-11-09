# Contributing to Linux Security Vulnerability Analyzer

Thank you for your interest in contributing to the Linux Security Vulnerability Analyzer! This document provides guidelines for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Submitting Changes](#submitting-changes)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Enhancements](#suggesting-enhancements)

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. Please be respectful and constructive in all interactions.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- **Clear Title**: Descriptive summary of the issue
- **Steps to Reproduce**: Detailed steps to reproduce the problem
- **Expected Behavior**: What you expected to happen
- **Actual Behavior**: What actually happened
- **Environment**:
  - OS and version (e.g., Ubuntu 22.04, RHEL 8.5)
  - Script version
  - Relevant system information
- **Logs/Output**: Include relevant error messages or output

### Suggesting Enhancements

Enhancement suggestions are welcome! Please provide:

- **Clear Title**: Descriptive summary of the enhancement
- **Use Case**: Explain why this enhancement would be useful
- **Proposed Solution**: If you have ideas on how to implement it
- **Alternatives**: Any alternative solutions you've considered

### Pull Requests

We actively welcome your pull requests:

1. Fork the repository
2. Create a new branch from `main` for your feature/fix
3. Make your changes following our coding standards
4. Test your changes on multiple distributions if possible
5. Update documentation as needed
6. Submit a pull request with a clear description

## Development Setup

### Prerequisites

- Linux system (Debian, RHEL, or SUSE-based)
- Bash 4.0 or higher
- Standard Linux utilities (awk, grep, sed, etc.)
- Root access for testing (VM or container recommended)

### Testing Environment

We recommend testing in virtual machines or containers:

```bash
# Test on Ubuntu
docker run -it --rm ubuntu:22.04 /bin/bash

# Test on CentOS
docker run -it --rm centos:8 /bin/bash

# Test on Fedora
docker run -it --rm fedora:latest /bin/bash
```

### Running Tests

Before submitting changes:

1. **Syntax Check**:
   ```bash
   bash -n linux_security_audit.sh
   ```

2. **ShellCheck** (recommended):
   ```bash
   shellcheck linux_security_audit.sh
   ```

3. **Test on Multiple Distributions**:
   - Ubuntu/Debian
   - RHEL/CentOS/Rocky
   - Fedora
   - SUSE/openSUSE

4. **Test Both Root and Non-Root Modes**:
   ```bash
   # With root
   sudo ./linux_security_audit.sh

   # Without root
   ./linux_security_audit.sh
   ```

## Coding Standards

### Shell Script Guidelines

1. **Bash Version**: Target Bash 4.0+ for broad compatibility
2. **Set Safety Options**: Use `set -euo pipefail`
3. **Use ShellCheck**: Ensure code passes ShellCheck validation
4. **Quoting**: Always quote variables: `"${VAR}"`
5. **Functions**: Use descriptive function names with comments
6. **Error Handling**: Implement proper error handling with meaningful messages
7. **Constants**: Use `readonly` for constants in UPPER_CASE
8. **Variables**: Use lowercase with underscores for variables

### Code Style

```bash
# Good example
check_security_feature() {
    local feature_name="${1:-}"
    local status="${2:-}"

    if [[ -z "${feature_name}" ]]; then
        log_message "ERROR: Feature name required"
        return 1
    fi

    # Implementation here
}

# Use consistent indentation (4 spaces)
if [[ condition ]]; then
    do_something
    if [[ nested_condition ]]; then
        do_nested_thing
    fi
fi
```

### Documentation

- **Comments**: Add clear comments for complex logic
- **Function Headers**: Document purpose, parameters, and return values
- **Inline Documentation**: Explain non-obvious code sections

Example:
```bash
################################################################################
# Function: check_package_cves
# Description: Check for known CVEs in installed packages
# Parameters:
#   $1 - package: Package name to check
#   $2 - version: Package version
# Returns:
#   0 on success, 1 on error
################################################################################
check_package_cves() {
    local package="${1:-}"
    local version="${2:-}"
    # Implementation...
}
```

### Security Considerations

When contributing security-related code:

1. **No Hardcoded Credentials**: Never include passwords or API keys
2. **Input Validation**: Validate all user inputs
3. **Secure Temporary Files**: Use `mktemp` for temporary files
4. **Path Safety**: Be cautious with file paths and command injection
5. **Privilege Checks**: Properly handle root vs non-root execution
6. **Cleanup**: Ensure temporary files/directories are cleaned up

## Submitting Changes

### Commit Messages

Follow these guidelines for commit messages:

```
Short summary (50 chars or less)

More detailed explanation if necessary. Wrap at 72 characters.
Explain what changed, why, and any important details.

- Bullet points are fine
- Use present tense: "Add feature" not "Added feature"
- Reference issues: Fixes #123
```

Examples:
```
Add support for AlmaLinux detection

- Detect AlmaLinux as RHEL family
- Add AlmaLinux-specific package manager commands
- Update OS detection logic

Fixes #45
```

### Pull Request Process

1. **Update Documentation**: Update README.md and relevant docs
2. **Update CHANGELOG**: Add entry to CHANGELOG.md
3. **Test Thoroughly**: Test on multiple distributions
4. **One Feature Per PR**: Keep pull requests focused
5. **Describe Changes**: Provide clear PR description
6. **Link Issues**: Reference related issues

### PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Breaking change (fix or feature causing existing functionality to change)
- [ ] Documentation update

## Testing
- [ ] Tested on Ubuntu/Debian
- [ ] Tested on RHEL/CentOS
- [ ] Tested on Fedora
- [ ] Tested on SUSE
- [ ] Tested with root privileges
- [ ] Tested without root privileges
- [ ] Passes ShellCheck

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-reviewed the code
- [ ] Commented complex sections
- [ ] Updated documentation
- [ ] Added/updated tests if applicable
- [ ] No new warnings generated
```

## Distribution Support

When adding support for new distributions:

1. Update `detect_os()` function
2. Add package manager commands in `init_package_manager()`
3. Test all security checks on the new distribution
4. Update documentation listing supported distributions
5. Add distribution to testing checklist

## CVE Database Integration

When improving CVE detection:

1. Ensure CVE data is cached appropriately
2. Include CVSS score validation
3. Provide remediation commands for all package managers
4. Test CVE detection accuracy
5. Document CVE data sources

## Documentation

Update documentation when you:

- Add new features
- Change existing functionality
- Add new command-line options
- Support new distributions
- Change output format

Documentation files to consider:
- README.md
- INSTALL.md
- docs/ directory files
- Inline code comments

## Getting Help

If you need help with your contribution:

- Open an issue with your question
- Tag it as "question"
- Provide context about what you're trying to accomplish

## Recognition

All contributors will be recognized in the project. Significant contributions may result in being listed as a maintainer.

Thank you for contributing to making Linux systems more secure!

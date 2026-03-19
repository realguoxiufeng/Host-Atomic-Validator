# Host Atomic Validator

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
[![MITRE ATT&CK](https://img.shields.io/badge/ATT%26CK-67%20Techniques-blue)](https://attack.mitre.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)]()
[![Release](https://img.shields.io/badge/Release-v1.0.0-blue)](https://github.com/realguoxiufeng/Host-Atomic-Validator/releases/tag/v1.0.0)

A security testing tool for executing MITRE ATT&CK atomic tests. This project provides batch execution capabilities for attack simulation tests and automated report generation, supporting both Windows and Linux platforms.

English | [中文文档](README_CN.md)

## Features

- **Cross-Platform Support**: Windows and Linux implementations
- **Batch Execution**: Run multiple atomic tests in sequence
- **Category-Based Testing**: Execute tests by MITRE ATT&CK tactic categories
- **Automated Reporting**: Generate HTML, Excel, Word, and text reports
- **Risk Assessment**: Built-in risk level classification for techniques
- **Progress Tracking**: Detailed logging and execution summaries

## Supported MITRE ATT&CK Tactics

| Category | Description | Example Techniques |
|----------|-------------|-------------------|
| Execution | Execute malicious code | T1059, T1064, T1204, T1569 |
| Persistence | Maintain system access | T1136, T1547, T1053, T1543 |
| Privilege Escalation | Gain higher privileges | T1548, T1068, T1134, T1055 |
| Defense Evasion | Avoid detection | T1027, T1112, T1070, T1036 |
| Discovery | Explore environment | T1083, T1018, T1057, T1518 |
| Lateral Movement | Move through network | T1021, T1077, T1091, T1550 |
| Credential Access | Steal credentials | T1003, T1552, T1555 |
| Command and Control | Establish control channel | T1071, T1095, T1132 |

## System Requirements

### Windows
- Windows Server 2016/2019/2022 or Windows 10/11
- PowerShell 5.0 or higher
- `goart-windows.exe` (required executor)

### Linux
- Linux operating system
- Bash 4.0+
- `goart-linux` (required executor)

### Python (for report generation)
- Python 3.6+
- Dependencies: pandas, openpyxl, python-docx

## Installation

```bash
# Clone the repository
git clone https://github.com/realguoxiufeng/Host-Atomic-Validator.git
cd Host-Atomic-Validator

# Install Python dependencies
pip install -r basforwindows/requirements.txt
# or for Linux
pip install -r basforlinux/requirements.txt
```

## Download Executors

The `goart-windows.exe` and `goart-linux` executors are required to run the tests. Download them from the [Latest Release](https://github.com/realguoxiufeng/Host-Atomic-Validator/releases/latest).

| Platform | File | Download |
|----------|------|----------|
| Windows | `goart-windows.exe` | [Download](https://github.com/realguoxiufeng/Host-Atomic-Validator/releases/download/v1.0.0/goart-windows.exe) |
| Linux | `goart-linux` | [Download](https://github.com/realguoxiufeng/Host-Atomic-Validator/releases/download/v1.0.0/goart-linux) |

### Executor Setup

After downloading, place the binaries in their respective directories:

```bash
# Windows: Place in
basforwindows/goart-windows.exe

# Linux: Place in and set execute permission
basforlinux/goart-linux
chmod +x basforlinux/goart-linux
```

## Quick Start

### Windows

```powershell
# Navigate to Windows directory
cd basforwindows

# Set execution policy (if needed)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Run all tests
.\run_all_atomics.ps1

# Run specific technique
.\run_all_atomics.ps1 -t T1059

# Run by category
.\run_all_atomics.ps1 -c execution

# Dry run (preview without execution)
.\run_all_atomics.ps1 -DryRun
```

### Linux

```bash
# Navigate to Linux directory
cd basforlinux

# Set execute permissions
chmod +x run_all_atomics.sh goart-linux

# Run all tests
sudo ./run_all_atomics.sh

# Run specific technique
sudo ./run_all_atomics.sh -t T1059

# Run by category
sudo ./run_all_atomics.sh -c execution
```

### Generate Reports

```bash
# Generate all report formats
python analyze_atomic_logs2.py

# Generate specific format
python analyze_atomic_logs2.py --format html
python analyze_atomic_logs2.py --format excel
python analyze_atomic_logs2.py --format docx
```

## Project Structure

```
Host-Atomic-Validator/
├── basforwindows/           # Windows implementation
│   ├── run_all_atomics.ps1  # Main PowerShell script
│   ├── analyze_atomic_logs2.py  # Report generator
│   ├── TTPs.md              # Supported techniques list
│   ├── configs/             # Configuration files
│   ├── logs/                # Test logs (auto-created)
│   └── reports/             # Generated reports (auto-created)
├── basforlinux/             # Linux implementation
│   ├── run_all_atomics.sh   # Main Bash script
│   ├── analyze_atomic_logs2.py  # Report generator
│   ├── TTPs.md              # Supported techniques list
│   ├── configs/             # Configuration files
│   ├── logs/                # Test logs (auto-created)
│   └── reports/             # Generated reports (auto-created)
├── CLAUDE.md                # Claude Code guidance
├── LICENSE                  # MIT License
└── README.md                # This file
```

## Command Line Options

### Windows (PowerShell)

| Parameter | Alias | Description |
|-----------|-------|-------------|
| `-Help` | `-h` | Show help message |
| `-TechniqueId` | `-t` | Run specific technique test |
| `-Category` | `-c` | Run tests by category |
| `-ListFile` | `-l` | Read technique list from file |
| `-SkipFailed` | `-s` | Skip failed tests and continue |
| `-DryRun` | `-d` | Show tests without executing |
| `-Verbose` | `-v` | Show detailed output |
| `-Timeout` | - | Test timeout in seconds (default: 300) |

### Linux (Bash)

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message |
| `-t TECHNIQUE_ID` | Run specific technique test |
| `-c CATEGORY` | Run tests by category |
| `-l LIST_FILE` | Read technique list from file |
| `-s, --skip-failed` | Skip failed tests and continue |
| `-d, --dry-run` | Show tests without executing |
| `-v, --verbose` | Show detailed output |
| `--timeout SEC` | Test timeout in seconds (default: 300) |

## Report Formats

The `analyze_atomic_logs2.py` script generates reports in multiple formats:

| Format | Description |
|--------|-------------|
| HTML | Interactive report with charts and statistics |
| Excel | Multi-sheet workbook with detailed analysis |
| Word | Professional document for formal reporting |
| Text | Plain text format for quick review |

## Security Warning

**This tool executes actual attack simulation tests. Please read and understand the following:**

1. **Isolated Environment**: Only run tests in isolated, dedicated test environments
2. **System Impact**: Tests may modify system state, create files, or change configurations
3. **Authorization**: Ensure you have proper authorization before testing
4. **Data Protection**: Protect sensitive information in logs and reports
5. **Not for Production**: Do not run in production environments

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 realguoxiufeng

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Acknowledgments

- [MITRE ATT&CK Framework](https://attack.mitre.org/) - Adversary tactics, techniques, and procedures
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) - Atomic test library
- [Red Canary](https://redcanary.com/) - Atomic Red Team maintainers

## Related Resources

- [MITRE ATT&CK Official Site](https://attack.mitre.org/)
- [Atomic Red Team Project](https://github.com/redcanaryco/atomic-red-team)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors and contributors are not responsible for any misuse or damage caused by this tool. Users are responsible for ensuring they have proper authorization before conducting any security testing. Always comply with applicable laws and regulations in your jurisdiction.
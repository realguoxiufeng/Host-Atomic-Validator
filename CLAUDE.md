# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Host Atomic Validator is a security testing tool for executing MITRE ATT&CK atomic tests. It contains platform-specific implementations for Windows and Linux, enabling batch execution of attack simulation tests and automated report generation.

## Repository Structure

```
basforwindows/     # Windows implementation
basforlinux/       # Linux implementation
```

Each platform directory contains:
- `run_all_atomics.ps1` or `run_all_atomics.sh` - Main execution script
- `analyze_atomic_logs2.py` - Log analyzer and report generator
- `goart-windows.exe` or `goart-linux` - Execution engine (binary)
- `logs/` - Test execution logs (auto-created)
- `reports/` - Generated reports (auto-created)
- `configs/execution_plan.json` - Technique configuration by category
- `requirements.txt` - Python dependencies

## Commands

### Windows (PowerShell)

```powershell
# Run all tests
.\run_all_atomics.ps1

# Run specific technique
.\run_all_atomics.ps1 -t T1059

# Run by category
.\run_all_atomics.ps1 -c execution
.\run_all_atomics.ps1 -c persistence
.\run_all_atomics.ps1 -c privilege-escalation
.\run_all_atomics.ps1 -c defense-evasion
.\run_all_atomics.ps1 -c discovery
.\run_all_atomics.ps1 -c lateral-movement

# Run from config file
.\run_all_atomics.ps1 -l techniques.txt

# Dry run (preview without execution)
.\run_all_atomics.ps1 -DryRun

# Skip failed tests and continue
.\run_all_atomics.ps1 -l techniques.txt -SkipFailed

# Set custom timeout (default: 300 seconds)
.\run_all_atomics.ps1 -t T1059 -Timeout 600
```

### Linux (Bash)

```bash
# Run all tests
./run_all_atomics.sh

# Run specific technique
./run_all_atomics.sh -t T1059

# Run by category
./run_all_atomics.sh -c execution

# Run from config file
./run_all_atomics.sh -l techniques.txt

# Dry run
./run_all_atomics.sh -d

# Skip failed tests
./run_all_atomics.sh -l techniques.txt -s
```

### Log Analysis

```bash
# Install dependencies first
pip install -r requirements.txt

# Generate all report formats (HTML, Excel, Text, Word)
python analyze_atomic_logs2.py

# Generate specific format
python analyze_atomic_logs2.py --format html
python analyze_atomic_logs2.py --format excel
python analyze_atomic_logs2.py --format docx
python analyze_atomic_logs2.py --format text

# Specify directories
python analyze_atomic_logs2.py --log-dir ./logs --report-dir ./reports

# Specify output filename
python analyze_atomic_logs2.py --output my_report
```

## Architecture

### Execution Flow

1. `run_all_atomics.ps1/sh` reads technique list from args, category, or config file
2. Calls `goart-windows.exe` or `goart-linux` binary to execute each atomic test
3. Logs are written to `logs/{TechniqueID}_{Timestamp}.log`
4. Summary report saved to `reports/test_summary_{Timestamp}.txt`

### Report Generation

`analyze_atomic_logs2.py` parses `.log` files and generates:
- HTML reports with charts and statistics
- Excel workbooks with multiple sheets (Summary, Details, By Technique, By Tactic, Errors)
- Word documents for formal reporting
- Plain text reports

### Technique Categories

| Category | Examples |
|----------|----------|
| execution | T1059, T1064, T1204, T1569 |
| persistence | T1136, T1547, T1053, T1543 |
| privilege-escalation | T1548, T1068, T1134, T1055 |
| defense-evasion | T1027, T1112, T1070, T1036 |
| discovery | T1083, T1018, T1057, T1518 |
| lateral-movement | T1021, T1077, T1091, T1550 |
| credential-access | T1003, T1552, T1555 |
| command-and-control | T1071, T1095, T1132 |

## Configuration

### execution_plan.json

Defines techniques grouped by category with timeout and parallelism settings.

### Config File Format (techniques.txt)

```
# Comments are ignored
T1059
T1021.004 - Remote Services: SSH
```

## Dependencies

Python packages (required for report generation):
- pandas
- openpyxl
- python-docx

## Security Warning

These tools execute actual attack simulation tests. Run only in isolated test environments. Tests may modify system state, create files, or change configurations.
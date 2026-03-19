# MITRE ATT&CK Batch Test Script - User Manual

## Overview

`run_all_atomics.ps1` is a PowerShell script for batch executing MITRE ATT&CK atomic tests on Windows systems. Compatible with Windows Server 2016/2019 and Windows 10/11.

---

## System Requirements

### Operating Systems
- Windows Server 2016
- Windows Server 2019
- Windows Server 2022
- Windows 10
- Windows 11

### Software Dependencies
- PowerShell 5.0 or higher
- `goart-windows.exe` (required)
- (Optional) Atomic Red Team project

---

## Installation

### Directory Structure

```
basforwindows/
├── run_all_atomics.ps1    # Main script
├── goart-windows.exe      # Executor (required)
├── logs/                  # Log directory (auto-created)
├── reports/               # Report directory (auto-created)
├── configs/               # Config directory (auto-created)
└── README.md              # This document
```

### Setup Steps

```powershell
# 1. Set execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# 2. Place goart-windows.exe in the script directory

# 3. (Optional) Clone Atomic Red Team project
git clone https://github.com/redcanaryco/atomic-red-team.git "C:\AtomicRedTeam\atomic-red-team"
```

---

## Command Line Parameters

| Parameter | Alias | Description | Default |
|-----------|-------|-------------|---------|
| `-Help` | `-h` | Show help message | - |
| `-TechniqueId` | `-t` | Run specific technique test | - |
| `-Category` | `-c` | Run tests by category | - |
| `-ListFile` | `-l` | Read technique list from file | - |
| `-SkipFailed` | `-s` | Skip failed tests and continue | $false |
| `-DryRun` | `-d` | Show tests without executing | $false |
| `-Verbose` | `-v` | Show detailed output | $false |
| `-MaxParallel` | - | Max parallel processes | 1 |
| `-Timeout` | - | Test timeout (seconds) | 300 |
| `-Index` | - | Specify test index | - |

---

## Usage Examples

### Basic Usage

```powershell
# Show help
.\run_all_atomics.ps1 -Help

# Run all tests
.\run_all_atomics.ps1

# Dry run mode (preview without execution)
.\run_all_atomics.ps1 -DryRun
```

### Test Specific Technique

```powershell
# Single technique
.\run_all_atomics.ps1 -t T1059

# Sub-technique
.\run_all_atomics.ps1 -t T1021.004

# With specific index
.\run_all_atomics.ps1 -t T1059 -Index 1

# With verbose output
.\run_all_atomics.ps1 -t T1059 -Verbose
```

### Test by Category

```powershell
# Execution tests
.\run_all_atomics.ps1 -c execution

# Persistence tests
.\run_all_atomics.ps1 -c persistence

# Privilege escalation tests
.\run_all_atomics.ps1 -c privilege-escalation

# Defense evasion tests
.\run_all_atomics.ps1 -c defense-evasion

# Discovery tests
.\run_all_atomics.ps1 -c discovery

# Lateral movement tests
.\run_all_atomics.ps1 -c lateral-movement

# Collection tests
.\run_all_atomics.ps1 -c collection

# Exfiltration tests
.\run_all_atomics.ps1 -c exfiltration

# Command and control tests
.\run_all_atomics.ps1 -c command-and-control
```

### Read from File

```powershell
# From config file
.\run_all_atomics.ps1 -l techniques.txt

# With verbose output
.\run_all_atomics.ps1 -l techniques.txt -Verbose

# Skip failures and continue
.\run_all_atomics.ps1 -l techniques.txt -SkipFailed
```

### Advanced Usage

```powershell
# Set timeout to 600 seconds
.\run_all_atomics.ps1 -t T1059 -Timeout 600

# Combined parameters
.\run_all_atomics.ps1 -c execution -SkipFailed -Verbose -Timeout 600

# Run with specific index and skip failures
.\run_all_atomics.ps1 -t T1059 -Index 1 -SkipFailed -Verbose
```

---

## Config File Format

The config file supports the following formats:

```
# This is a comment, will be skipped

# Basic format - technique ID only
T1059
T1021.004

# With description (description is ignored)
T1021.004 - Remote Services: SSH
T1059.001 - PowerShell

# Empty lines are ignored

T1078
```

### Example Config File (techniques.txt)

```
# Execution tests
T1059
T1059.001
T1059.003

# Persistence tests
T1053
T1136

# Lateral movement tests
T1021
T1021.001
```

---

## Test Categories

| Category | Description | Techniques |
|----------|-------------|------------|
| execution | Execute malicious code | T1059, T1064, T1204, T1569, T1203 |
| persistence | Maintain system access | T1136, T1547, T1053, T1505, T1137 |
| privilege-escalation | Gain higher privileges | T1548, T1068, T1134, T1547, T1574 |
| defense-evasion | Avoid detection | T1027, T1112, T1070, T1140, T1548 |
| discovery | Explore environment | T1016, T1018, T1033, T1046, T1082 |
| lateral-movement | Move through network | T1021, T1077, T1091, T1210, T1550 |
| collection | Collect target data | T1005, T1113, T1114, T1115, T1119 |
| exfiltration | Steal data | T1020, T1030, T1041, T1048, T1052 |
| command-and-control | Establish control channel | T1071, T1095, T1132, T1571, T1572 |

---

## Output Files

### Log Files

- **Location:** `logs/` directory
- **Format:** `{TechniqueID}_{Timestamp}.log`
- **Example:** `T1059_20240101_120000.log`

### Summary Report

- **Location:** `reports/` directory
- **Format:** `test_summary_{Timestamp}.txt`
- **Example:** `test_summary_20240101_120000.txt`

### Sample Report Output

```
MITRE ATT&CK Test Summary Report
Test Time: 2024-01-01 12:00:00
========================================

T1059: SUCCESS
T1068: FAILED
T1070: SUCCESS

Summary:
Total: 3
Success: 2
Failed: 1
Skipped: 0
========================================
Detailed logs: logs\
```

---

## Execution Flow

```
Start
  |
  v
Parse Parameters
  |
  v
Check Dependencies -----> Failed ----> Exit
  |
  v Success
  |
Initialize Directories
  |
  v
Get Technique List
  |
  v
Display Techniques
  |
  v
Confirm Execution <------ User Cancel ----> Exit
  |
  v Confirmed
  |
Batch Execute Tests
  |
  +---> Success ---> Record Success
  |
  +---> Failed ---> Skip?
                     |
                     +-- No ---> Stop
                     |
                     +-- Yes ---> Continue
  |
  v
Generate Summary Report
  |
  v
End
```

---

## Error Handling

### Common Errors and Solutions

| Error | Cause | Solution |
|-------|-------|----------|
| `goart-windows.exe not found` | Executor not in script directory | Copy goart-windows.exe to script directory |
| `Config file not found` | Wrong config file path | Check file path is correct |
| `Cannot parse technique ID` | Invalid technique ID format | Use format: T1059 or T1021.004 |
| `Test timed out` | Test exceeded timeout limit | Use `-Timeout` parameter to increase |
| `Unknown category` | Invalid category name | Use supported category names |

### Execution Policy Issues

If you encounter execution policy restrictions:

```powershell
# Method 1: Bypass temporarily
PowerShell -ExecutionPolicy Bypass -File .\run_all_atomics.ps1

# Method 2: Change current user policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Method 3: Remove signing requirement
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
```

---

## Advanced Configuration

### Modify Default Paths

Edit these variables in the script:

```powershell
$script:GOART_PATH = Join-Path $script:BASE_DIR "goart-windows.exe"
$script:LOG_DIR = Join-Path $script:BASE_DIR "logs"
$script:REPORT_DIR = Join-Path $script:BASE_DIR "reports"
$script:ATOMICS_PATH = "C:\AtomicRedTeam\atomic-red-team"
```

### Modify Default Values

```powershell
$script:TIMEOUT = 300        # Default timeout in seconds
$script:MAX_PARALLEL = 1     # Default parallel processes
```

### Add Custom Category

Add to `Get-TechniquesByCategory` function:

```powershell
"your-category" {
    return @("T1001", "T1002", "T1003")
}
```

---

## Security Notes

1. **Test Environment:** Always test in isolated environment first
2. **Permissions:** Some tests require administrator privileges
3. **Logging:** Tests generate logs - protect sensitive information
4. **Production:** Use caution when testing in production systems

---

## Troubleshooting

### Enable Verbose Output

```powershell
.\run_all_atomics.ps1 -t T1059 -Verbose
```

### Use Dry Run Mode

```powershell
.\run_all_atomics.ps1 -DryRun
```

### Check Log Files

```powershell
# View latest log
Get-ChildItem logs\ | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content
```

---

## Quick Reference

### Parameter Aliases

| Full Parameter | Alias |
|----------------|-------|
| `-Help` | `-h` |
| `-TechniqueId` | `-t` |
| `-Category` | `-c` |
| `-ListFile` | `-l` |
| `-SkipFailed` | `-s` |
| `-DryRun` | `-d` |
| `-Verbose` | `-v` |

### Common Commands

```powershell
# Show help
.\run_all_atomics.ps1 -h

# Run single test
.\run_all_atomics.ps1 -t T1059

# Run category tests
.\run_all_atomics.ps1 -c execution

# Run from file
.\run_all_atomics.ps1 -l techniques.txt

# Preview without running
.\run_all_atomics.ps1 -d

# Run with all options
.\run_all_atomics.ps1 -t T1059 -s -v -Timeout 600
```

---

## Appendix

### MITRE ATT&CK Technique ID Format

- **Main technique:** T + 4 digits (e.g., T1059)
- **Sub-technique:** T + 4 digits + . + 3 digits (e.g., T1021.004)

### Related Resources

- [MITRE ATT&CK Official Site](https://attack.mitre.org/)
- [Atomic Red Team Project](https://github.com/redcanaryco/atomic-red-team)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

---

**Version:** 1.0.0
**Author:** BAS for Windows
**Last Updated:** 2024
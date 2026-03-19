#Requires -Version 5.0

<#
.SYNOPSIS
    MITRE ATT&CK Batch Test Script (Windows Version)
.DESCRIPTION
    Batch execute MITRE ATT&CK atomic tests on Windows
    Compatible with Windows Server 2016/2019 and Windows 10/11
.NOTES
    Author: BAS for Windows
    Version: 1.0.0
#>

# ============================================
# Script Parameters (MUST be at the beginning)
# ============================================
param(
    [Alias('t')]
    [string]$TechniqueId,

    [Alias('c')]
    [string]$Category,

    [Alias('l')]
    [string]$ListFile,

    [Alias('h')]
    [switch]$Help,

    [Alias('s')]
    [switch]$SkipFailed,

    [Alias('d')]
    [switch]$DryRun,

    [Alias('v')]
    [switch]$Verbose,

    [int]$MaxParallel = 1,

    [int]$Timeout = 300,

    [string]$Index
)

$ErrorActionPreference = "Stop"

# ============================================
# Configuration Variables
# ============================================
$script:BASE_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrEmpty($script:BASE_DIR)) {
    $script:BASE_DIR = $PWD.Path
}

$script:GOART_PATH = Join-Path $script:BASE_DIR "goart-windows.exe"
$script:LOG_DIR = Join-Path $script:BASE_DIR "logs"
$script:REPORT_DIR = Join-Path $script:BASE_DIR "reports"
$script:CONFIG_DIR = Join-Path $script:BASE_DIR "configs"
$script:ATOMICS_PATH = "C:\AtomicRedTeam\atomic-red-team"

$script:SKIP_FAILED = $false
$script:DRY_RUN = $false
$script:VERBOSE = $false
$script:MAX_PARALLEL = 1
$script:TIMEOUT = 300
$script:TEST_INDEX = ""

$script:TotalTests = 0
$script:SuccessCount = 0
$script:FailureCount = 0
$script:SkippedCount = 0

# ============================================
# Logging Functions
# ============================================
function Write-LogInfo {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] INFO: $Message"
}

function Write-LogSuccess {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-LogWarning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-LogError {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Write-LogVerbose {
    param([string]$Message)
    if ($script:VERBOSE) {
        Write-LogInfo $Message
    }
}

# ============================================
# Help Information
# ============================================
function Show-Help {
    Write-Host ""
    Write-Host "========================================"
    Write-Host "MITRE ATT&CK Batch Test Script (Windows)"
    Write-Host "========================================"
    Write-Host ""
    Write-Host "Usage: .\run_all_atomics.ps1 [Options]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -h, -Help                  Show this help message"
    Write-Host "  -t, -TechniqueId ID        Run specific technique (e.g., T1059, T1021.004)"
    Write-Host "  -c, -Category CATEGORY     Run tests by category"
    Write-Host "  -l, -ListFile FILE         Read technique list from file"
    Write-Host "  -s, -SkipFailed            Skip failed tests and continue"
    Write-Host "  -d, -DryRun                Show tests without executing"
    Write-Host "  -v, -Verbose               Show detailed output"
    Write-Host "  -MaxParallel N             Max parallel processes (default: 1)"
    Write-Host "  -Timeout SEC               Test timeout in seconds (default: 300)"
    Write-Host "  -Index INDEX               Specify test index number"
    Write-Host ""
    Write-Host "Categories:"
    Write-Host "  execution             Execution tests"
    Write-Host "  persistence           Persistence tests"
    Write-Host "  privilege-escalation  Privilege escalation tests"
    Write-Host "  defense-evasion       Defense evasion tests"
    Write-Host "  discovery             Discovery tests"
    Write-Host "  lateral-movement      Lateral movement tests"
    Write-Host "  collection            Collection tests"
    Write-Host "  exfiltration          Exfiltration tests"
    Write-Host "  command-and-control   Command and control tests"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\run_all_atomics.ps1                          Run all tests"
    Write-Host "  .\run_all_atomics.ps1 -t T1059                 Run specific technique"
    Write-Host "  .\run_all_atomics.ps1 -c execution             Run execution category"
    Write-Host "  .\run_all_atomics.ps1 -l techniques.txt        Read from file"
    Write-Host "  .\run_all_atomics.ps1 -l techniques.txt -v     With verbose output"
    Write-Host "  .\run_all_atomics.ps1 -t T1059 -s              Skip failures"
    Write-Host ""
    Write-Host "Config File Format:"
    Write-Host "  T1021.004"
    Write-Host "  T1021.004 - Remote Services: SSH"
    Write-Host "  # Comments are ignored"
    Write-Host ""
}

# ============================================
# Initialize Directories
# ============================================
function Initialize-Directories {
    $dirs = @($script:LOG_DIR, $script:REPORT_DIR, $script:CONFIG_DIR)
    foreach ($dir in $dirs) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-LogVerbose "Created directory: $dir"
        }
    }
}

# ============================================
# Check Dependencies
# ============================================
function Test-Dependencies {
    Write-LogInfo "Checking dependencies..."

    if (-not (Test-Path $script:GOART_PATH)) {
        Write-LogError "goart-windows.exe not found: $($script:GOART_PATH)"
        Write-LogInfo "Please ensure goart-windows.exe is in the script directory"
        exit 1
    }

    Write-LogVerbose "Found goart: $($script:GOART_PATH)"

    if (-not (Test-Path $script:ATOMICS_PATH)) {
        Write-LogWarning "Atomic Red Team directory not found: $($script:ATOMICS_PATH)"
        Write-LogInfo "Clone with: git clone https://github.com/redcanaryco/atomic-red-team.git"
    }
    else {
        Write-LogVerbose "Found Atomic Red Team: $($script:ATOMICS_PATH)"
    }

    $osInfo = $null
    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    }
    catch {
        try {
            $osInfo = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue
        }
        catch { }
    }

    if ($null -ne $osInfo) {
        Write-LogInfo "OS: $($osInfo.Caption)"
        Write-LogInfo "Version: $($osInfo.Version)"
    }

    Write-LogSuccess "Dependency check completed"
}

# ============================================
# Parse Technique ID
# ============================================
function Get-TechniqueId {
    param([string]$Line)

    $Line = $Line.Trim()

    if ([string]::IsNullOrEmpty($Line)) { return $null }
    if ($Line.StartsWith("#")) { return $null }

    if ($Line -match '\b(T\d{4}(?:\.\d{3})?)\b') {
        return $Matches[1]
    }

    return $null
}

# ============================================
# Read Techniques from File
# ============================================
function Get-TechniquesFromFile {
    param([string]$FilePath)

    if (-not (Test-Path $FilePath)) {
        Write-LogError "Config file not found: $FilePath"
        return $null
    }

    Write-LogInfo "Reading config file: $FilePath"

    $techniques = New-Object System.Collections.Generic.List[string]
    $lineNumber = 0

    $lines = Get-Content -Path $FilePath -Encoding UTF8
    foreach ($line in $lines) {
        $lineNumber++
        $techId = Get-TechniqueId -Line $line

        if (-not [string]::IsNullOrEmpty($techId)) {
            if (-not $techniques.Contains($techId)) {
                $techniques.Add($techId) | Out-Null
                Write-LogVerbose "Parsed technique ID: $techId (line $lineNumber)"
            }
        }
    }

    return $techniques.ToArray()
}

# ============================================
# Get All Techniques
# ============================================
function Get-AllTechniques {
    $atomicsPath = Join-Path $script:ATOMICS_PATH "atomics"

    if (Test-Path $atomicsPath) {
        $folders = Get-ChildItem -Path $atomicsPath -Directory -ErrorAction SilentlyContinue
        $techniques = @()
        foreach ($folder in $folders) {
            if ($folder.Name -match '^T\d{4}(\.\d{3})?$') {
                $techniques += $folder.Name
            }
        }
        if ($techniques.Count -gt 0) {
            return ($techniques | Sort-Object)
        }
    }

    return @(
        "T1003", "T1005", "T1012", "T1016", "T1018", "T1021", "T1027",
        "T1036", "T1046", "T1047", "T1049", "T1053", "T1055", "T1059",
        "T1068", "T1070", "T1071", "T1072", "T1078", "T1082", "T1083",
        "T1090", "T1095", "T1098", "T1102", "T1105", "T1106", "T1110",
        "T1112", "T1113", "T1119", "T1120", "T1124", "T1125", "T1129",
        "T1132", "T1133", "T1134", "T1135", "T1136", "T1137", "T1140",
        "T1176", "T1187", "T1189", "T1190", "T1195", "T1197", "T1199",
        "T1200", "T1201", "T1202", "T1203", "T1204", "T1205", "T1210",
        "T1211", "T1212", "T1213", "T1216", "T1217", "T1218", "T1219",
        "T1220", "T1221", "T1222"
    )
}

# ============================================
# Get Techniques by Category
# ============================================
function Get-TechniquesByCategory {
    param([string]$Category)

    $categoryMap = @{
        "execution"             = @("T1059", "T1064", "T1204", "T1569", "T1203")
        "persistence"           = @("T1136", "T1547", "T1053", "T1505", "T1137")
        "privilege-escalation"  = @("T1548", "T1068", "T1134", "T1547", "T1574")
        "defense-evasion"       = @("T1027", "T1112", "T1070", "T1140", "T1548")
        "discovery"             = @("T1016", "T1018", "T1033", "T1046", "T1082")
        "lateral-movement"      = @("T1021", "T1077", "T1091", "T1210", "T1550")
        "collection"            = @("T1005", "T1113", "T1114", "T1115", "T1119")
        "exfiltration"          = @("T1020", "T1030", "T1041", "T1048", "T1052")
        "command-and-control"   = @("T1071", "T1095", "T1132", "T1571", "T1572")
    }

    $catKey = $Category.ToLower()
    if ($categoryMap.ContainsKey($catKey)) {
        return $categoryMap[$catKey]
    }

    Write-LogError "Unknown category: $Category"
    Write-LogInfo "Supported categories: execution, persistence, privilege-escalation, defense-evasion, discovery, lateral-movement, collection, exfiltration, command-and-control"
    exit 1
}

# ============================================
# Run Single Test
# ============================================
function Invoke-TechniqueTest {
    param(
        [string]$Technique,
        [string]$TestIndex
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $logFile = Join-Path $script:LOG_DIR "${Technique}_${timestamp}.log"

    $indexInfo = ""
    if (-not [string]::IsNullOrEmpty($TestIndex)) {
        $indexInfo = " (index: $TestIndex)"
    }
    Write-LogInfo "Starting test: $Technique$indexInfo"

    $arguments = @("--technique", $Technique)

    if (-not [string]::IsNullOrEmpty($TestIndex) -and $TestIndex -ne "-1") {
        $arguments += @("--index", $TestIndex)
    }

    if (Test-Path $script:ATOMICS_PATH) {
        $arguments += @("--local-atomics-path", $script:ATOMICS_PATH)
    }

    if ($script:DRY_RUN) {
        $argStr = $arguments -join " "
        Write-LogInfo "Would execute: $($script:GOART_PATH) $argStr"
        return $true
    }

    try {
        $argStr = $arguments -join " "
        Write-LogVerbose "Executing: $($script:GOART_PATH) $argStr"

        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = $script:GOART_PATH
        $processInfo.Arguments = $argStr
        $processInfo.RedirectStandardOutput = $true
        $processInfo.RedirectStandardError = $true
        $processInfo.UseShellExecute = $false
        $processInfo.CreateNoWindow = $true

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processInfo

        $process.Start() | Out-Null

        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()

        $timeoutMs = $script:TIMEOUT * 1000
        $exited = $process.WaitForExit($timeoutMs)

        if (-not $exited) {
            Write-LogError "Test $Technique timed out ($($script:TIMEOUT)s)"
            try { $process.Kill() } catch { }
            return $false
        }

        $logContent = $stdout + [Environment]::NewLine + $stderr
        Set-Content -Path $logFile -Value $logContent -Encoding UTF8

        if ($script:VERBOSE) {
            Write-Host $logContent
        }

        if ($logContent -match "Test completed successfully|successfully executed|Test Passed") {
            Write-LogSuccess "Test $Technique completed successfully"
            return $true
        }
        elseif ($logContent -match "Test failed|failed to execute|Error executing") {
            Write-LogWarning "Test $Technique failed"
            return $false
        }

        if ($process.ExitCode -eq 0) {
            Write-LogSuccess "Test $Technique completed (exit code: 0)"
            return $true
        }
        else {
            Write-LogWarning "Test $Technique completed (exit code: $($process.ExitCode))"
            return $false
        }
    }
    catch {
        Write-LogError "Test $Technique execution error: $_"
        return $false
    }
}

# ============================================
# Run Batch Tests
# ============================================
function Invoke-BatchTests {
    param([string[]]$Techniques)

    $script:TotalTests = $Techniques.Count
    $script:SuccessCount = 0
    $script:FailureCount = 0
    $script:SkippedCount = 0

    Write-LogInfo "Starting batch tests, total: $($script:TotalTests) techniques"

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $summaryFile = Join-Path $script:REPORT_DIR "test_summary_$timestamp.txt"

    $headerContent = "MITRE ATT&CK Test Summary Report" + [Environment]::NewLine
    $headerContent += "Test Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" + [Environment]::NewLine
    $headerContent += "========================================" + [Environment]::NewLine + [Environment]::NewLine
    Set-Content -Path $summaryFile -Value $headerContent -Encoding UTF8

    $current = 0
    foreach ($technique in $Techniques) {
        $current++
        Write-LogInfo "[$current/$($script:TotalTests)] Processing: $technique"

        $success = Invoke-TechniqueTest -Technique $technique -TestIndex $script:TEST_INDEX

        if ($success) {
            $script:SuccessCount++
            $resultLine = "$technique`: SUCCESS"
        }
        else {
            $script:FailureCount++
            $resultLine = "$technique`: FAILED"
        }

        Add-Content -Path $summaryFile -Value $resultLine -Encoding UTF8

        if (-not $success -and -not $script:SKIP_FAILED) {
            Write-LogError "Test failed, stopping execution (use -SkipFailed to continue)"
            break
        }

        Start-Sleep -Milliseconds 500
    }

    Write-Host ""
    Write-Host "========================================"
    Write-Host "Test Summary:"
    Write-Host "Total: $($script:TotalTests)"
    Write-Host "Success: $($script:SuccessCount)"
    Write-Host "Failed: $($script:FailureCount)"
    Write-Host "Skipped: $($script:SkippedCount)"
    Write-Host "========================================"

    $footerContent = [Environment]::NewLine + "Summary:" + [Environment]::NewLine
    $footerContent += "Total: $($script:TotalTests)" + [Environment]::NewLine
    $footerContent += "Success: $($script:SuccessCount)" + [Environment]::NewLine
    $footerContent += "Failed: $($script:FailureCount)" + [Environment]::NewLine
    $footerContent += "Skipped: $($script:SkippedCount)" + [Environment]::NewLine
    $footerContent += "========================================" + [Environment]::NewLine
    $footerContent += "Detailed logs: $script:LOG_DIR\"
    Add-Content -Path $summaryFile -Value $footerContent -Encoding UTF8

    Write-LogInfo "Results saved to: $summaryFile"

    if ($script:FailureCount -eq 0) {
        Write-LogSuccess "All tests completed successfully!"
    }
    else {
        Write-LogWarning "$($script:FailureCount) test(s) failed"
    }
}

# ============================================
# Request Confirmation
# ============================================
function Request-UserConfirmation {
    param([string]$Message = "Continue with test execution?")

    Write-Host ""
    Write-Host "$Message (Y/N): " -NoNewline
    $response = [System.Console]::ReadLine()

    return ($response -match '^[Yy]')
}

# ============================================
# Main Execution
# ============================================

# Show help if requested
if ($Help) {
    Show-Help
    exit 0
}

# Set runtime variables
$script:SKIP_FAILED = $SkipFailed
$script:DRY_RUN = $DryRun
$script:VERBOSE = $Verbose
$script:MAX_PARALLEL = $MaxParallel
$script:TIMEOUT = $Timeout
$script:TEST_INDEX = $Index

# Initialize directories
Initialize-Directories

# Check dependencies
Test-Dependencies

# Get techniques to test
[string[]]$techniques = @()

if (-not [string]::IsNullOrEmpty($TechniqueId)) {
    $techId = Get-TechniqueId -Line $TechniqueId
    if ([string]::IsNullOrEmpty($techId)) {
        Write-LogError "Cannot parse technique ID: $TechniqueId"
        exit 1
    }
    $techniques = @($techId)
}
elseif (-not [string]::IsNullOrEmpty($Category)) {
    $techniques = Get-TechniquesByCategory -Category $Category
}
elseif (-not [string]::IsNullOrEmpty($ListFile)) {
    $techniques = Get-TechniquesFromFile -FilePath $ListFile
    if ($null -eq $techniques -or $techniques.Count -eq 0) {
        Write-LogError "No valid technique IDs found in: $ListFile"
        exit 1
    }
}
else {
    $techniques = Get-AllTechniques
}

if ($techniques.Count -eq 0) {
    Write-LogError "No techniques found to test"
    exit 1
}

# Display techniques
Write-LogInfo "Techniques to test ($($techniques.Count) total):"
$idx = 1
foreach ($tech in $techniques) {
    Write-Host "  $idx. $tech"
    $idx++
}

if ($script:DRY_RUN) {
    Write-LogInfo "Dry run mode, no tests will be executed"
    exit 0
}

Write-Host ""

# Confirm execution
if (-not (Request-UserConfirmation -Message "Continue with test execution?")) {
    Write-LogInfo "Test cancelled"
    exit 0
}

# Run batch tests
Invoke-BatchTests -Techniques $techniques
# Windows Installation Script for Network Flow Collector
# Run this script in PowerShell as Administrator

Write-Host "=== Network Flow Data Collector - Windows Installation ===" -ForegroundColor Green
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "WARNING: Not running as Administrator" -ForegroundColor Yellow
    Write-Host "Some features may not work properly without Administrator privileges" -ForegroundColor Yellow
    Write-Host "It's recommended to run this script as Administrator" -ForegroundColor Yellow
    Write-Host ""
}

# Check Python installation
Write-Host "Checking Python installation..." -ForegroundColor Cyan

try {
    $pythonVersion = python --version 2>&1
    Write-Host "✓ Python found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ Python not found!" -ForegroundColor Red
    Write-Host "Please install Python from https://www.python.org/downloads/" -ForegroundColor Red
    Write-Host "Make sure to check 'Add Python to PATH' during installation" -ForegroundColor Red
    exit 1
}

# Check pip
Write-Host "Checking pip..." -ForegroundColor Cyan
try {
    $pipVersion = pip --version 2>&1
    Write-Host "✓ pip found: $pipVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ pip not found!" -ForegroundColor Red
    Write-Host "Please install pip or reinstall Python with pip included" -ForegroundColor Red
    exit 1
}

# Check for Npcap
Write-Host "Checking for Npcap installation..." -ForegroundColor Cyan

$npcapInstalled = $false

# Check registry for Npcap
try {
    $npcapKey = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" -ErrorAction Stop
    Write-Host "✓ Npcap found: $($npcapKey.DisplayName)" -ForegroundColor Green
    $npcapInstalled = $true
} catch {
    # Check for WinPcap as alternative
    try {
        $winpcapKey = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" -ErrorAction Stop
        Write-Host "⚠ WinPcap found (Npcap is preferred): $($winpcapKey.DisplayName)" -ForegroundColor Yellow
        $npcapInstalled = $true
    } catch {
        Write-Host "✗ Npcap/WinPcap not found!" -ForegroundColor Red
    }
}

if (-not $npcapInstalled) {
    Write-Host ""
    Write-Host "IMPORTANT: Npcap is required for packet capture on Windows!" -ForegroundColor Red
    Write-Host "Please download and install Npcap from: https://nmap.org/npcap/" -ForegroundColor Yellow
    Write-Host ""
    $choice = Read-Host "Continue installation without Npcap? (y/n)"
    if ($choice -ne 'y' -and $choice -ne 'Y') {
        Write-Host "Installation cancelled. Please install Npcap first." -ForegroundColor Red
        exit 1
    }
}

# Install Python packages
Write-Host ""
Write-Host "Installing Python packages..." -ForegroundColor Cyan

try {
    pip install -r requirements.txt
    Write-Host "✓ Python packages installed successfully" -ForegroundColor Green
} catch {
    Write-Host "✗ Error installing Python packages" -ForegroundColor Red
    Write-Host "Error: $_" -ForegroundColor Red
    
    # Try alternative installation
    Write-Host ""
    Write-Host "Trying alternative installation method..." -ForegroundColor Yellow
    
    $packages = @("scapy==2.5.0", "pandas==2.1.4", "numpy==1.24.3", "matplotlib==3.7.2", "seaborn==0.13.2", "pywin32==306")
    
    foreach ($package in $packages) {
        try {
            pip install $package
            Write-Host "✓ Installed: $package" -ForegroundColor Green
        } catch {
            Write-Host "✗ Failed: $package" -ForegroundColor Red
        }
    }
}

# Test installation
Write-Host ""
Write-Host "Testing installation..." -ForegroundColor Cyan

$testScript = @"
import sys
try:
    import scapy
    import pandas
    import numpy
    import matplotlib
    import seaborn
    print("✓ All required packages imported successfully")
    
    # Test Scapy Windows functionality
    from scapy.all import get_if_list
    interfaces = get_if_list()
    print(f"✓ Found {len(interfaces)} network interfaces")
    
except ImportError as e:
    print(f"✗ Import error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"⚠ Warning: {e}")
"@

python -c $testScript

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "=== Installation Complete! ===" -ForegroundColor Green
    Write-Host ""
    Write-Host "Usage Examples:" -ForegroundColor Cyan
    Write-Host "  # List available network interfaces" -ForegroundColor White
    Write-Host "  python network_flow_collector_windows.py --list-interfaces" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  # Start collecting network flow data" -ForegroundColor White
    Write-Host "  python network_flow_collector_windows.py -o training_data.csv -t 300" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  # Collect from specific interface" -ForegroundColor White
    Write-Host "  python network_flow_collector_windows.py -i \"Ethernet\" -o flows.csv" -ForegroundColor Gray
    Write-Host ""
    
    if ($isAdmin) {
        Write-Host "Note: Running as Administrator - optimal performance available" -ForegroundColor Green
    } else {
        Write-Host "Note: For best performance, run the collector as Administrator" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "Files created:" -ForegroundColor Cyan
    Write-Host "  - network_flow_collector_windows.py  (Main collector)" -ForegroundColor Gray
    Write-Host "  - flow_analyzer_windows.py           (Data analyzer)" -ForegroundColor Gray
    Write-Host "  - flow_labeler_windows.py            (Data labeler)" -ForegroundColor Gray
    Write-Host "  - requirements.txt                   (Dependencies)" -ForegroundColor Gray
    
} else {
    Write-Host ""
    Write-Host "=== Installation Issues Detected ===" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please check the error messages above and:" -ForegroundColor Yellow
    Write-Host "1. Make sure Python is properly installed" -ForegroundColor White
    Write-Host "2. Install Npcap from https://nmap.org/npcap/" -ForegroundColor White
    Write-Host "3. Try running as Administrator" -ForegroundColor White
    Write-Host "4. Check your internet connection for package downloads" -ForegroundColor White
}

Write-Host ""
Write-Host "Press any key to continue..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
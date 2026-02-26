#!/usr/bin/env python3
"""
Npcap Installation Checker and Fixer
Chi tiết check Npcap installation và hướng dẫn fix
"""

import os
import sys
import subprocess
import winreg

def check_npcap_detailed():
    """Chi tiết check Npcap installation"""
    print("=== Detailed Npcap Check ===")
    
    checks = {
        "Npcap Registry": False,
        "WinPcap Registry": False,
        "Npcap Service": False,
        "Npcap Driver": False,
        "Scapy Detection": False
    }
    
    # 1. Check Npcap Registry
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                           "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\NpcapInst")
        display_name = winreg.QueryValueEx(key, "DisplayName")[0]
        version = winreg.QueryValueEx(key, "DisplayVersion")[0]
        winreg.CloseKey(key)
        
        print(f"✅ Npcap Registry: {display_name} v{version}")
        checks["Npcap Registry"] = True
        
    except FileNotFoundError:
        print("❌ Npcap Registry: Not found")
    except Exception as e:
        print(f"⚠️  Npcap Registry: Error - {e}")
    
    # 2. Check WinPcap Registry (fallback)
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                           "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\WinPcapInst")
        display_name = winreg.QueryValueEx(key, "DisplayName")[0]
        version = winreg.QueryValueEx(key, "DisplayVersion")[0]
        winreg.CloseKey(key)
        
        print(f"⚠️  WinPcap Registry: {display_name} v{version} (outdated)")
        checks["WinPcap Registry"] = True
        
    except FileNotFoundError:
        print("❌ WinPcap Registry: Not found")
    except Exception as e:
        print(f"⚠️  WinPcap Registry: Error - {e}")
    
    # 3. Check Npcap Service
    try:
        result = subprocess.run(['sc', 'query', 'npcap'], 
                              capture_output=True, text=True, shell=True)
        if 'RUNNING' in result.stdout:
            print("✅ Npcap Service: Running")
            checks["Npcap Service"] = True
        elif 'STOPPED' in result.stdout:
            print("⚠️  Npcap Service: Stopped (can be started)")
            checks["Npcap Service"] = True
        else:
            print("❌ Npcap Service: Not found")
    except Exception as e:
        print(f"⚠️  Npcap Service: Error checking - {e}")
    
    # 4. Check Npcap Driver Files
    npcap_paths = [
        "C:\\Windows\\System32\\Npcap\\",
        "C:\\Windows\\System32\\drivers\\npcap.sys",
        "C:\\Windows\\SysWOW64\\Npcap\\wpcap.dll"
    ]
    
    found_files = 0
    for path in npcap_paths:
        if os.path.exists(path):
            print(f"✅ Found: {path}")
            found_files += 1
        else:
            print(f"❌ Missing: {path}")
    
    if found_files >= 2:
        checks["Npcap Driver"] = True
        print("✅ Npcap Driver: Files present")
    else:
        print("❌ Npcap Driver: Missing files")
    
    # 5. Check Scapy Detection
    try:
        from scapy.all import get_if_list, conf
        interfaces = get_if_list()
        
        # Check if Scapy detects proper interfaces
        if len(interfaces) > 0:
            print(f"✅ Scapy Detection: {len(interfaces)} interfaces")
            checks["Scapy Detection"] = True
            
            # Show some interface info
            for i, iface in enumerate(interfaces[:3]):
                print(f"   {i+1}. {iface}")
        else:
            print("❌ Scapy Detection: No interfaces")
            
    except Exception as e:
        print(f"❌ Scapy Detection: Error - {e}")
    
    return checks

def check_nmap_installation():
    """Check if Nmap is installed"""
    print("\n=== Nmap Installation Check ===")
    
    try:
        result = subprocess.run(['nmap', '--version'], 
                              capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            version_line = result.stdout.split('\n')[0]
            print(f"✅ Nmap: {version_line}")
            return True
        else:
            print("❌ Nmap: Not working properly")
            return False
    except Exception as e:
        print(f"❌ Nmap: Not found - {e}")
        return False

def suggest_fixes(checks):
    """Suggest fixes based on check results"""
    print("\n=== Suggested Fixes ===")
    
    if not any(checks.values()):
        print("🔧 MAJOR ISSUE: No packet capture capability detected!")
        print()
        print("📥 Download and install Npcap:")
        print("   1. Go to: https://nmap.org/npcap/")
        print("   2. Download latest version")
        print("   3. Run as Administrator")
        print("   4. Check 'Install Npcap in WinPcap API-compatible Mode'")
        print("   5. Restart computer")
        
    elif checks["WinPcap Registry"] and not checks["Npcap Registry"]:
        print("🔧 UPGRADE NEEDED: WinPcap detected, upgrade to Npcap!")
        print()
        print("📥 Install Npcap (will replace WinPcap):")
        print("   1. Download from: https://nmap.org/npcap/")
        print("   2. Uninstall WinPcap first (recommended)")
        print("   3. Install Npcap as Administrator")
        
    elif checks["Npcap Registry"] and not checks["Npcap Service"]:
        print("🔧 SERVICE ISSUE: Npcap installed but service not running!")
        print()
        print("🚀 Start Npcap service:")
        print("   sc start npcap")
        print("   Or restart computer")
        
    elif checks["Npcap Registry"] and not checks["Scapy Detection"]:
        print("🔧 SCAPY ISSUE: Npcap installed but Scapy can't detect!")
        print()
        print("🔄 Try these:")
        print("   1. Restart Python/terminal")
        print("   2. Reinstall Scapy: pip uninstall scapy && pip install scapy")
        print("   3. Run as Administrator")
        
    else:
        print("✅ Everything looks good!")
        print()
        print("If still having issues:")
        print("   1. Try running as Administrator")
        print("   2. Restart computer")
        print("   3. Check Windows Defender/Firewall")

def download_npcap_instructions():
    """Detailed Npcap download instructions"""
    print("\n=== Npcap Installation Instructions ===")
    print()
    print("🌐 Official Download:")
    print("   URL: https://nmap.org/npcap/")
    print("   File: npcap-X.XX.exe (latest version)")
    print()
    print("⚙️ Installation Steps:")
    print("   1. Right-click installer -> 'Run as administrator'")
    print("   2. Accept license agreement")
    print("   3. ✅ Check 'Install Npcap in WinPcap API-compatible Mode'")
    print("   4. ✅ Check 'Support raw 802.11 traffic' (optional)")
    print("   5. Click 'Install'")
    print("   6. Restart computer when prompted")
    print()
    print("🔍 Verification:")
    print("   After restart, run this script again to verify")
    print()
    print("❓ Alternative (if issues persist):")
    print("   1. Uninstall any existing WinPcap/Npcap")
    print("   2. Clean install Npcap")
    print("   3. Reboot")

def main():
    print("🔍 Npcap Installation Diagnostic Tool")
    print("=" * 50)
    
    # Run checks
    checks = check_npcap_detailed()
    
    # Check Nmap
    nmap_installed = check_nmap_installation()
    
    # Summary
    print(f"\n=== Summary ===")
    working_checks = sum(checks.values())
    total_checks = len(checks)
    
    print(f"Working: {working_checks}/{total_checks} checks passed")
    
    if working_checks >= 3:
        print("🎉 Status: GOOD - Should work!")
    elif working_checks >= 1:
        print("⚠️  Status: PARTIAL - May work with fixes")
    else:
        print("❌ Status: FAILED - Needs Npcap installation")
    
    # Suggestions
    suggest_fixes(checks)
    
    # Always show download instructions
    download_npcap_instructions()

if __name__ == "__main__":
    main()
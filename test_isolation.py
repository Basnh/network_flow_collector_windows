#!/usr/bin/env python3
"""
Diagnostic script to test network isolation directly.
Run this as Administrator to test if Disable-NetAdapter works.
"""
import subprocess
import json
import ctypes
import sys
import time

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_ps(cmd):
    result = subprocess.run(
        ['powershell', '-Command', cmd],
        capture_output=True, text=True, shell=False
    )
    return result

def list_adapters():
    print("\n=== Listing ALL network adapters ===")
    result = run_ps('Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MediaType | ConvertTo-Json')
    if result.returncode != 0:
        print(f"ERROR: {result.stderr}")
        return []
    try:
        adapters = json.loads(result.stdout)
        if isinstance(adapters, dict):
            adapters = [adapters]
        for a in adapters:
            print(f"  Name: {a.get('Name')!r:30s} Status: {a.get('Status'):10s}  Type: {a.get('MediaType')}")
        return adapters
    except Exception as e:
        print(f"Parse error: {e}")
        print(f"Raw output: {result.stdout}")
        return []

def test_disable(adapter_name):
    print(f"\n=== Testing: Disable-NetAdapter '{adapter_name}' ===")
    result = run_ps(f'Disable-NetAdapter -Name "{adapter_name}" -Confirm:$false')
    print(f"Return code: {result.returncode}")
    if result.stdout:
        print(f"STDOUT: {result.stdout}")
    if result.stderr:
        print(f"STDERR: {result.stderr}")
    return result.returncode == 0

def test_enable(adapter_name):
    print(f"\n=== Testing: Enable-NetAdapter '{adapter_name}' ===")
    result = run_ps(f'Enable-NetAdapter -Name "{adapter_name}" -Confirm:$false')
    print(f"Return code: {result.returncode}")
    if result.stdout:
        print(f"STDOUT: {result.stdout}")
    if result.stderr:
        print(f"STDERR: {result.stderr}")
    return result.returncode == 0

if __name__ == '__main__':
    print("=" * 60)
    print("  NETWORK ISOLATION DIAGNOSTIC TOOL")
    print("=" * 60)

    # Check admin
    admin = is_admin()
    print(f"\n[*] Running as Administrator: {'YES ✓' if admin else 'NO ✗ (REQUIRED!)'}")
    if not admin:
        print("\n!!! ERROR: You MUST run this script as Administrator !!!")
        print("    Right-click cmd/PowerShell → 'Run as administrator'")
        print("    Then: python test_isolation.py")
        input("\nPress Enter to exit...")
        sys.exit(1)

    # List adapters
    adapters = list_adapters()
    if not adapters:
        print("\nNo adapters found!")
        input("Press Enter to exit...")
        sys.exit(1)

    # Pick the first non-loopback adapter
    physical = [a for a in adapters if a.get('Status') in ('Up', 'Disconnected')]
    if not physical:
        physical = adapters
    
    print(f"\n[*] Adapters available for testing: {[a.get('Name') for a in physical]}")
    
    # Ask user
    print("\nWhich adapter do you want to test? (copy name exactly from list above)")
    adapter_name = input("--> ").strip()
    if not adapter_name:
        adapter_name = physical[0].get('Name')
        print(f"Using: {adapter_name}")

    # Test disable
    print(f"\n[*] Will DISABLE adapter '{adapter_name}' in 3 seconds...")
    print("[*] Network will be cut. It will auto-re-enable in 10 seconds.")
    for i in range(3, 0, -1):
        print(f"    {i}...")
        time.sleep(1)

    ok = test_disable(adapter_name)
    if ok:
        print(f"\n✓ SUCCESS: Adapter '{adapter_name}' disabled!")
        print("[*] Waiting 10 seconds then re-enabling...")
        time.sleep(10)
        ok2 = test_enable(adapter_name)
        if ok2:
            print(f"✓ SUCCESS: Adapter '{adapter_name}' re-enabled!")
        else:
            print(f"✗ FAILED to re-enable. Run manually: Enable-NetAdapter -Name \"{adapter_name}\" -Confirm:$false")
    else:
        print(f"\n✗ FAILED: Could not disable adapter '{adapter_name}'")
        print("   Check the STDERR output above for the exact error.")

    input("\nPress Enter to exit...")

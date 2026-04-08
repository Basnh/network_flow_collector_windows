#!/usr/bin/env python3
"""
Check what flows are in the database
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, NetworkFlow

with app.app_context():
    print("=" * 60)
    print("Network Flows in Database")
    print("=" * 60)
    
    # Get total count
    total = NetworkFlow.query.count()
    print(f"\n📊 Total flows: {total}")
    
    # Show recent flows
    flows = NetworkFlow.query.order_by(NetworkFlow.created_at.desc()).limit(20).all()
    
    if not flows:
        print("\n⚠️  No flows found in database!")
        print("\nPossible reasons:")
        print("  1. Network flow collector is not running")
        print("  2. No agents have submitted flows yet")
        print("  3. Server is not receiving POST requests to /api/submit_flow")
    else:
        print(f"\n📋 Recent {min(len(flows), 20)} flows:")
        print("-" * 60)
        for i, flow in enumerate(flows, 1):
            print(f"\n{i}. Flow ID: {flow.id}")
            print(f"   Src: {flow.src_ip}:{flow.src_port}")
            print(f"   Dst: {flow.dst_ip}:{flow.dst_port}")
            print(f"   Protocol: {flow.protocol}")
            print(f"   Threat Score: {flow.threat_score}")
            print(f"   Malicious: {flow.is_malicious}")
            print(f"   Classification: {flow.classification}")
            print(f"   Created: {flow.created_at}")
    
    # Check for port 6000 specifically
    print("\n" + "=" * 60)
    print("Searching for port 6000 connections...")
    print("=" * 60)
    
    port_6000_flows = NetworkFlow.query.filter(
        (NetworkFlow.src_port == 6000) | (NetworkFlow.dst_port == 6000)
    ).all()
    
    if port_6000_flows:
        print(f"✅ Found {len(port_6000_flows)} flows on port 6000:")
        for flow in port_6000_flows:
            print(f"   {flow.src_ip}:{flow.src_port} → {flow.dst_ip}:{flow.dst_port}")
    else:
        print("❌ No flows found on port 6000")
    
    # Check if there are any flows at all
    if total == 0:
        print("\n" + "=" * 60)
        print("⚠️  DATABASE IS EMPTY!")
        print("=" * 60)
        print("\nTo generate test flows, make sure:")
        print("1. Server is running on port 5000")
        print("2. Network flow collector is running and collecting")
        print("3. Check network_flow_collector_windows.py logs")

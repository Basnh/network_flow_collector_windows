#!/usr/bin/env python3
"""
Security Management System Setup and Run Script
"""

import os
import sys
import subprocess
import time
import threading
import argparse

def install_dependencies():
    """Install required Python packages"""
    print("Installing dependencies...")
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
        print("Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error installing dependencies: {e}")
        return False

def setup_database():
    """Initialize the database"""
    print("Setting up database...")
    try:
        # Import here to avoid issues if dependencies aren't installed yet
        from app import app, db
        
        with app.app_context():
            db.create_all()
            print("Database initialized successfully")
            return True
    except Exception as e:
        print(f"Error setting up database: {e}")
        return False

def run_web_server():
    """Run the Flask web server"""
    print("Starting Security Management Web Server...")
    try:
        from app import app
        app.run(host='0.0.0.0', port=5000, debug=False)
    except Exception as e:
        print(f"Error starting web server: {e}")

def run_agent_client(server_url):
    """Run the security agent client"""
    print(f"Starting Security Agent Client connecting to {server_url}...")
    try:
        from security_agent_client import SecurityAgentClient
        
        agent = SecurityAgentClient(server_url)
        agent.start()
        
        print("Agent client started. Press Ctrl+C to stop")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping agent...")
        agent.stop()
    except Exception as e:
        print(f"Error running agent client: {e}")

def integrate_with_existing_collector(collector_script_path, server_url):
    """Integrate with existing network flow collector"""
    print(f"Integrating with network collector: {collector_script_path}")
    
    try:
        # Add current directory to Python path
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        
        # Import the integration function
        from security_agent_client import integrate_with_flow_collector
        
        # Import the network collector (adjust import as needed)
        collector_dir = os.path.dirname(collector_script_path)
        sys.path.insert(0, collector_dir)
        
        from network_flow_collector_windows import WindowsNetworkFlowCollector
        
        # Create collector instance
        collector = WindowsNetworkFlowCollector(
            output_file="network_flows_with_security.csv",
            timeout=120,
            hex_payload=True
        )
        
        # Integrate with security system
        agent_client = integrate_with_flow_collector(collector, server_url)
        
        print(f"Integration complete. Starting network collection...")
        print(f"Data will be sent to security server: {server_url}")
        
        # Start collection
        collector.start_collection()
        
    except Exception as e:
        print(f"Error integrating with collector: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Security Management System Setup and Runner')
    parser.add_argument('command', choices=['setup', 'server', 'agent', 'integrate'], 
                       help='Command to run')
    parser.add_argument('--server-url', default='http://localhost:5000', 
                       help='Security management server URL')
    parser.add_argument('--collector-path', 
                       help='Path to network flow collector script (for integrate command)')
    parser.add_argument('--install-deps', action='store_true',
                       help='Install dependencies before running')
    
    args = parser.parse_args()
    
    # Change to script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    if args.command == 'setup':
        print("=== Security Management System Setup ===")
        
        # Install dependencies
        if not install_dependencies():
            sys.exit(1)
        
        # Setup database
        if not setup_database():
            sys.exit(1)
        
        print("\n=== Setup Complete ===")
        print("To start the system:")
        print(f"1. Start server: {sys.executable} {__file__} server")
        print(f"2. Start agents: {sys.executable} {__file__} agent --server-url http://YOUR-SERVER:5000")
        print("3. Open browser to http://localhost:5000")
    
    elif args.command == 'server':
        if args.install_deps:
            install_dependencies()
            setup_database()
        
        print("=== Starting Security Management Server ===")
        print("Web interface will be available at: http://localhost:5000")
        print("Press Ctrl+C to stop the server")
        
        try:
            run_web_server()
        except KeyboardInterrupt:
            print("\nServer stopped")
    
    elif args.command == 'agent':
        if args.install_deps:
            install_dependencies()
        
        print("=== Starting Security Agent Client ===")
        
        try:
            run_agent_client(args.server_url)
        except KeyboardInterrupt:
            print("\nAgent stopped")
    
    elif args.command == 'integrate':
        if not args.collector_path:
            print("Error: --collector-path is required for integrate command")
            sys.exit(1)
        
        if not os.path.exists(args.collector_path):
            print(f"Error: Collector script not found: {args.collector_path}")
            sys.exit(1)
        
        if args.install_deps:
            install_dependencies()
        
        print("=== Integrating with Network Flow Collector ===")
        
        try:
            integrate_with_existing_collector(args.collector_path, args.server_url)
        except KeyboardInterrupt:
            print("\nIntegrated collector stopped")

if __name__ == '__main__':
    main()
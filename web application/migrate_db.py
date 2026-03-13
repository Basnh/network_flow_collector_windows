#!/usr/bin/env python3
"""
Database migration script to add new columns for network isolation feature
"""

import sys
from sqlalchemy import text
from app import app, db

def migrate_database():
    """Add new columns to agent table for network isolation"""
    
    with app.app_context():
        try:
            # Connect to database
            with db.engine.connect() as connection:
                print("🔄 Running database migration...")
                
                # Add pending_command column if not exists
                print("  - Adding 'pending_command' column...")
                connection.execute(text("""
                    ALTER TABLE agent 
                    ADD COLUMN IF NOT EXISTS pending_command TEXT
                """))
                
                # Add network_adapter_name column if not exists
                print("  - Adding 'network_adapter_name' column...")
                connection.execute(text("""
                    ALTER TABLE agent 
                    ADD COLUMN IF NOT EXISTS network_adapter_name VARCHAR(100)
                """))
                
                connection.commit()
                print("✅ Migration completed successfully!")
                return True
                
        except Exception as e:
            print(f"❌ Migration failed: {e}")
            return False

if __name__ == '__main__':
    success = migrate_database()
    sys.exit(0 if success else 1)

import sqlite3
import bcrypt

def create_admin():
    db_path = 'vapt_database.db'
    hashed = bcrypt.hashpw(b'havoc_admin', bcrypt.gensalt()).decode('utf-8')
    try:
        conn = sqlite3.connect(db_path, timeout=30.0)
        cursor = conn.cursor()
        
        # Insert admin user. Ignore if already exists.
        cursor.execute('''
            INSERT OR IGNORE INTO users (first_name, last_name, email, password, role, plan)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', ('Admin', 'System', 'admin@havoc.com', hashed, 'Admin', 'team'))
        
        conn.commit()
        conn.close()
        print('Admin user created/verified successfully.')
    except Exception as e:
        print(f"Error creating admin: {e}")

if __name__ == "__main__":
    create_admin()

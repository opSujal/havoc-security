import sqlite3
import bcrypt
from datetime import datetime
from typing import List, Tuple, Dict

class DatabaseManager:
    """Manages SQLite database for VAPT findings"""
    
    def __init__(self, db_path: str = 'vapt_database.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY,
                cve TEXT,
                type TEXT,
                severity TEXT,
                epss_score REAL,
                description TEXT,
                affected_url TEXT,
                target TEXT,
                status TEXT,
                discovered_date TIMESTAMP,
                remediation_date TIMESTAMP,
                ai_solution TEXT,
                user_id INTEGER,
                proof_request TEXT,
                proof_response TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id),
                UNIQUE(cve, target, user_id)
            )
        ''')
        # Migrate existing databases that pre-date these columns
        for col in ['proof_request', 'proof_response']:
            try:
                cursor.execute(f'ALTER TABLE vulnerabilities ADD COLUMN {col} TEXT')
            except Exception:
                pass  # Column already exists
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY,
                target TEXT,
                scan_date TIMESTAMP,
                vulnerabilities_found INTEGER,
                duration_seconds INTEGER,
                status TEXT,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                first_name TEXT,
                last_name TEXT,
                email TEXT UNIQUE,
                password TEXT,
                role TEXT,
                org_id INTEGER,
                api_keys TEXT,
                activity_logs TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS organizations (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE,
                owner_id INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY,
                name TEXT,
                org_id INTEGER,
                target_domains TEXT,
                target_apis TEXT,
                scan_frequency TEXT,
                auth_credentials TEXT,
                allowed_modes TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        # self._insert_sample_data()  # Disabled sample data
    
    def clear_database(self, user_id: str):
        """Clear all data from database for a specific user"""
        conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM vulnerabilities WHERE user_id=?', (user_id,))
        cursor.execute('DELETE FROM scan_history WHERE user_id=?', (user_id,))
        conn.commit()
        conn.close()

    def _insert_sample_data(self):
        """Insert sample vulnerability data"""
        sample_data = [
            ('CVE-2024-0001', 'SQL Injection', 'Critical', 0.95, 'SQL injection in login form', '/login.php', 'example.com', 'Open'),
            ('CVE-2024-0002', 'Cross-Site Scripting (XSS)', 'High', 0.78, 'Reflected XSS in search parameter', '/search', 'example.com', 'In Progress'),
            ('CVE-2024-0003', 'Broken Authentication', 'Critical', 0.89, 'Weak password policy and session management', '/admin', 'example.com', 'Open'),
            ('CVE-2024-0004', 'SSRF', 'High', 0.72, 'Server-side request forgery in image proxy', '/image-proxy', 'api.example.com', 'Remediated'),
            ('CVE-2024-0005', 'IDOR', 'Medium', 0.55, 'Insecure direct object reference in user profiles', '/api/user/{id}', 'api.example.com', 'In Progress'),
        ]
        
        for data in sample_data:
            try:
                self.add_vulnerability(*data)
            except:
                pass
    
    def add_vulnerability(self, user_id: str, cve: str, vuln_type: str, severity: str,
                         epss_score: float, description: str, affected_url: str,
                         target: str, status: str = 'Open', ai_solution: str = '',
                         proof_request: str = '', proof_response: str = '') -> bool:
        """Add vulnerability to database with optional HTTP request/response proof."""
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO vulnerabilities
                (cve, type, severity, epss_score, description, affected_url, target, status,
                 discovered_date, ai_solution, user_id, proof_request, proof_response)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cve, target, user_id) DO UPDATE SET
                    type=excluded.type,
                    severity=excluded.severity,
                    epss_score=excluded.epss_score,
                    description=excluded.description,
                    affected_url=excluded.affected_url,
                    status=excluded.status,
                    discovered_date=excluded.discovered_date,
                    ai_solution=excluded.ai_solution,
                    proof_request=excluded.proof_request,
                    proof_response=excluded.proof_response
            ''', (cve, vuln_type, severity, epss_score, description, affected_url, target,
                  status, datetime.now(), ai_solution, user_id, proof_request, proof_response))

            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error adding vulnerability: {e}")
            return False
    
    def get_all_vulnerabilities(self, user_id: str) -> List[Tuple]:
        """Get all vulnerabilities for a specific user"""
        conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM vulnerabilities WHERE user_id=? ORDER BY epss_score DESC', (user_id,))
        vulns = cursor.fetchall()
        conn.close()
        
        return vulns
    
    def update_remediation_status(self, user_id: str, cve: str, status: str, remediation_date: str = None) -> bool:
        """Update vulnerability remediation status"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
            cursor = conn.cursor()
            
            if remediation_date is None and status == 'Remediated':
                remediation_date = datetime.now()
            
            cursor.execute('''
                UPDATE vulnerabilities 
                SET status = ?, remediation_date = ?
                WHERE cve = ? AND user_id = ?
            ''', (status, remediation_date, cve, user_id))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error updating status: {e}")
            return False
    
    def get_remediation_progress(self, user_id: str) -> Dict:
        """Get remediation progress statistics"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM vulnerabilities WHERE user_id=?', (user_id,))
            total = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE status='Remediated' AND user_id=?", (user_id,))
            remediated = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE status='In Progress' AND user_id=?", (user_id,))
            in_progress = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE (status='Open' OR status='Active') AND user_id=?", (user_id,))
            open_vulns = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'total': total,
                'remediated': remediated,
                'in_progress': in_progress,
                'open': open_vulns
            }
        except Exception as e:
            print(f"Error in get_remediation_progress: {e}")
            return {
                'total': 0,
                'remediated': 0,
                'in_progress': 0,
                'open': 0
            }
    
    def add_scan_history(self, user_id: str, target: str, vulns_found: int, duration: int, status: str = 'Completed') -> bool:
        """Add scan to history"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO scan_history (target, scan_date, vulnerabilities_found, duration_seconds, status, user_id)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (target, datetime.now(), vulns_found, duration, status, user_id))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error adding scan history: {e}")
            return False
    
    def get_scan_history(self, user_id: str) -> List[Tuple]:
        """Get scan history"""
        conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM scan_history WHERE user_id=? ORDER BY scan_date DESC', (user_id,))
        history = cursor.fetchall()
        conn.close()
        return history

    # --- Auth & User Management ---
    def add_user(self, first_name: str, last_name: str, email: str, password: str, role: str = 'User') -> dict:
        """Add a new user with bcrypt-hashed password"""
        try:
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (first_name, last_name, email, password, role)
                VALUES (?, ?, ?, ?, ?)
            ''', (first_name, last_name, email, hashed, role))
            user_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return {"id": user_id, "first_name": first_name, "last_name": last_name, "email": email, "role": role}
        except sqlite3.IntegrityError:
            return {"error": "Email already exists"}
        except Exception as e:
            return {"error": str(e)}

    def delete_user(self, user_id: str) -> bool:
        """Deletes a user account and all associated data from the database"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM vulnerabilities WHERE user_id=?', (user_id,))
            cursor.execute('DELETE FROM scan_history WHERE user_id=?', (user_id,))
            cursor.execute('DELETE FROM users WHERE id=?', (user_id,))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error deleting user: {e}")
            return False

    def verify_user(self, email: str, password: str) -> dict:
        """Verify user login using bcrypt"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute('SELECT id, first_name, last_name, email, role, password FROM users WHERE email=?', (email,))
            row = cursor.fetchone()
            conn.close()
            if row:
                stored_hash = row[5]
                # Support legacy plaintext passwords (migration path)
                try:
                    password_ok = bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
                except Exception:
                    password_ok = (stored_hash == password)
                if password_ok:
                    return {"id": row[0], "first_name": row[1], "last_name": row[2], "email": row[3], "role": row[4]}
            return None
        except Exception:
            return None

    def reset_password(self, email: str, old_password: str, new_password: str) -> bool:
        """Reset user password after verifying old password with bcrypt"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute('SELECT id, password FROM users WHERE email=?', (email,))
            row = cursor.fetchone()
            if not row:
                conn.close()
                return False

            stored_hash = row[1]
            # Support legacy plaintext passwords (migration path)
            try:
                password_ok = bcrypt.checkpw(old_password.encode('utf-8'), stored_hash.encode('utf-8'))
            except Exception:
                password_ok = (stored_hash == old_password)

            if not password_ok:
                conn.close()
                return False

            new_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cursor.execute('UPDATE users SET password=? WHERE email=?', (new_hash, email))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error resetting password: {e}")
            return False

    # --- Organization & Project Scaffolding ---
    def add_organization(self, name: str, owner_id: int):
        conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO organizations (name, owner_id) VALUES (?, ?)', (name, owner_id))
        conn.commit()
        conn.close()

    def add_project(self, name: str, org_id: int, target_domains: str):
        conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO projects (name, org_id, target_domains) VALUES (?, ?, ?)', (name, org_id, target_domains))
        conn.commit()
        conn.close()


import sqlite3
import security  # Import security functions

# This file contains all functions that interact with the SQLite database.

DB_FILE = "password_manager.db"

def db_connect():
    """Establishes a connection to the SQLite database."""
    return sqlite3.connect(DB_FILE)

def setup_database():
    """Creates the necessary tables if they don't exist."""
    conn = db_connect()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS master_user (
        id INTEGER PRIMARY KEY,
        password_hash TEXT NOT NULL,
        salt BLOB NOT NULL
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY,
        service TEXT NOT NULL UNIQUE,
        encrypted_data BLOB NOT NULL
    )
    """)
    conn.commit()
    conn.close()

def check_master_user_exists():
    """Checks if the master user has been created."""
    conn = db_connect()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM master_user")
    exists = cursor.fetchone()
    conn.close()
    return exists is not None

def create_master_user(password: str):
    """Creates the master user with a hashed password and a new salt."""
    salt = security.os.urandom(16)
    password_hash = security.base64.b64encode(security.derive_key(password, salt)).decode('utf-8')
    conn = db_connect()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO master_user (password_hash, salt) VALUES (?, ?)", (password_hash, salt))
    conn.commit()
    conn.close()

def verify_master_password(password: str):
    """Verifies the master password and returns the encryption key if correct."""
    conn = db_connect()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, salt FROM master_user WHERE id = 1")
    result = cursor.fetchone()
    conn.close()
    if result:
        stored_hash, salt = result
        entered_hash = security.base64.b64encode(security.derive_key(password, salt)).decode('utf-8')
        if entered_hash == stored_hash:
            return security.derive_key(password, salt)
    return None

def add_password(service: str, encrypted_data: bytes):
    """Adds a new encrypted password entry to the database."""
    conn = db_connect()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO passwords (service, encrypted_data) VALUES (?, ?)", (service, encrypted_data))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def update_password(service: str, encrypted_data: bytes):
    """Updates an existing encrypted password entry."""
    conn = db_connect()
    cursor = conn.cursor()
    cursor.execute("UPDATE passwords SET encrypted_data = ? WHERE service = ?", (encrypted_data, service))
    conn.commit()
    conn.close()

def get_all_services():
    """Retrieves a list of all stored services."""
    conn = db_connect()
    cursor = conn.cursor()
    cursor.execute("SELECT service FROM passwords ORDER BY service ASC")
    services = [row[0] for row in cursor.fetchall()]
    conn.close()
    return services

def get_encrypted_data(service: str):
    """Retrieves the encrypted data for a given service."""
    conn = db_connect()
    cursor = conn.cursor()
    cursor.execute("SELECT encrypted_data FROM passwords WHERE service = ?", (service,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def delete_password(service: str):
    """Deletes a password entry from the database."""
    conn = db_connect()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM passwords WHERE service = ?", (service,))
    conn.commit()
    conn.close()

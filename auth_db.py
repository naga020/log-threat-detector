import sqlite3
import bcrypt
from flask_login import UserMixin

DB_PATH = "users.db"


# ---------------------------
# USER CLASS
# ---------------------------
class User(UserMixin):
    def __init__(self, username, role):
        self.id = username
        self.role = role


# ---------------------------
# INIT USER DATABASE
# ---------------------------
def init_user_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'viewer'
    )
    """)

    conn.commit()
    conn.close()


# ---------------------------
# ADD USER (WITH HASH PASSWORD)
# ---------------------------
def add_user(username, password, role="viewer"):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    try:
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, hashed_pw, role)
        )
        conn.commit()
    except:
        pass  # user exists already

    conn.close()


# ---------------------------
# VERIFY LOGIN
# ---------------------------
def verify_user(username, password):

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT username, password, role FROM users WHERE username=?",
        (username,)
    )

    row = cursor.fetchone()
    conn.close()

    if row:
        stored_hash = row[1]

        # IMPORTANT: stored_hash must be bytes
        if bcrypt.checkpw(password.encode(), stored_hash):
            return {
                "username": row[0],
                "role": row[2]
            }

    return None
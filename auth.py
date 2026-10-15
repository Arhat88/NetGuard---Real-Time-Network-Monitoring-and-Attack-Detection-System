import hashlib
from database import get_connection, safe_execute


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def login(username, password):
    conn = get_connection()
    cursor = conn.cursor()
    hashed = hash_password(password)
    cursor.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, hashed)
    )
    user = cursor.fetchone()
    
    if user:
        # Update last_login
        cursor.execute(
            "UPDATE users SET last_login = datetime('now', 'localtime') WHERE user_id = ?",
            (user[0],)
        )
        conn.commit()
    
    conn.close()
    return user


def register(username, password, email):
    try:
        hashed = hash_password(password)
        safe_execute(
            "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
            (username, hashed, email)
        )
        return True
    except Exception as e:
        print(e)
        return False

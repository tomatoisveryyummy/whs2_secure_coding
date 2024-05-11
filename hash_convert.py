import sqlite3
import bcrypt

def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def update_database_with_hashed_passwords(db_path: str):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT id, password FROM users")
    users = cursor.fetchall()

    for user_id, plain_password in users:
        hashed_password = hash_password(plain_password)
        cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, user_id))

    conn.commit()
    conn.close()
    print("All passwords have been hashed and updated.")

update_database_with_hashed_passwords('shopping_mall.db')

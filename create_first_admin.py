import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

username = "admin"
password = "admin123"

try:
    cursor.execute("INSERT INTO admins (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    print(f"✅ Admin '{username}' created successfully.")
except sqlite3.IntegrityError:
    print("⚠️ Admin already exists.")
finally:
    conn.close()

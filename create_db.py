import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

# جدول المستخدمين
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        telegram_id INTEGER UNIQUE,
        username TEXT,
        full_name TEXT,
        role TEXT DEFAULT 'user'
    )
''')

# جدول سجل الأوامر
cursor.execute('''
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        command TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
''')

# جدول تسجيل الدخول للإدارة
cursor.execute('''
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )
''')

conn.commit()
conn.close()
print("✅ Database created successfully.")

# هذا السكربت يمكنك استدعاؤه من البوت لتسجيل المستخدم تلقائيًا في قاعدة SQLite

import sqlite3

DB = "database.db"

def register_user(telegram_id, username, full_name):
    try:
        conn = sqlite3.connect(DB)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT OR IGNORE INTO users (telegram_id, username, full_name)
            VALUES (?, ?, ?)
        ''', (telegram_id, username, full_name))

        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"❌ Error while registering user: {e}")
        return False

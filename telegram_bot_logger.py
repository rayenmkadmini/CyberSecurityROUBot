# 🔌 ربط البوت بقاعدة البيانات SQLite
import sqlite3
from telegram import Update
from telegram.ext import ContextTypes

DB = "database.db"

def insert_user(user):
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    telegram_id = user.id
    username = user.username or ""
    full_name = user.full_name or ""

    c.execute("SELECT * FROM users WHERE telegram_id = ?", (telegram_id,))
    if c.fetchone() is None:
        c.execute("INSERT INTO users (telegram_id, username, full_name) VALUES (?, ?, ?)",
                  (telegram_id, username, full_name))
        conn.commit()
    conn.close()

def log_command(user_id, command):
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute("SELECT id FROM users WHERE telegram_id = ?", (user_id,))
    user = c.fetchone()
    if user:
        user_id_db = user[0]
        c.execute("INSERT INTO logs (user_id, command) VALUES (?, ?)", (user_id_db, command))
        conn.commit()
    conn.close()

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3

app = Flask(__name__)
app.secret_key = "supersecretkey"

DB = "database.db"

def get_users():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT * FROM users")
    users = c.fetchall()
    conn.close()
    return users

def get_logs():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT logs.id, users.username, logs.command, logs.timestamp FROM logs JOIN users ON logs.user_id = users.id")
    logs = c.fetchall()
    conn.close()
    return logs

def check_admin(username, password):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT * FROM admins WHERE username = ? AND password = ?", (username, password))
    admin = c.fetchone()
    conn.close()
    return admin

def create_admin(username, password):
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("INSERT INTO admins (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        conn.close()
        return True
    except:
        return False

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if check_admin(username, password):
            session["admin"] = username
            return redirect(url_for("dashboard"))
        else:
            return render_template("login.html", error="❌ بيانات غير صحيحة")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("admin", None)
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if "admin" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html")

@app.route("/users")
def users():
    if "admin" not in session:
        return redirect(url_for("login"))
    return render_template("users.html", users=get_users())

@app.route("/usage")
def usage():
    if "admin" not in session:
        return redirect(url_for("login"))
    return render_template("usage.html", logs=get_logs())

@app.route("/add_admin", methods=["GET", "POST"])
def add_admin():
    if "admin" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        success = create_admin(username, password)
        message = "✅ تم إنشاء المشرف" if success else "❌ فشل في إنشاء المشرف"
        return render_template("add_admin.html", message=message)
    return render_template("add_admin.html")

@app.route("/api/users")
def api_users():
    return jsonify(get_users())

@app.route("/api/logs")
def api_logs():
    return jsonify(get_logs())

if __name__ == "__main__":
    app.run(debug=True)
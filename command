cyber_bot_project/
├── app.py                 ← تطبيق Flask (لوحة التحكم)
├── create_db.py           ← لإنشاء قاعدة البيانات
├── database.db            ← قاعدة بيانات SQLite (تُنشأ تلقائيًا)
├── bot.py                 ← كود البوت الرئيسي (Telegram bot)
├── requirements.txt       ← مكتبة المتطلبات (للتثبيت التلقائي)
├── /templates             ← ملفات HTML
│   ├── index.html
│   ├── login.html
│   ├── dashboard.html
│   ├── users.html
│   ├── usage.html
│   └── add_admin.html
├── /static
│   └── style.css          ← CSS لتصميم الواجهة
   



pip install -r requirements.txt


python create_db.py


python app.py


http://127.0.0.1:5000



python bot.py

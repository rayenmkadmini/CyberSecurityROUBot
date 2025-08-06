import json
import base64
import hashlib
import datetime
import ipaddress
import secrets
import uuid
import os
import re
import socket
import platform
import subprocess
import requests
import whois
import speech_recognition as sr
from pydub import AudioSegment
from gtts import gTTS
from telegram_bot_logger import insert_user, log_command
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters
from fuzzywuzzy import process, fuzz
from register_user import register_user

BOT_TOKEN = "8406135976:AAEkkKnbmD8awFGpRA_D4uXROaKcAvItBDU"

WELCOME_MESSAGE = (
    "👋 مرحبا بك في البوت الخاص ب ريان المقدميني\n\n"
    "📍 معهد تطاوين\n"
    "🏛️ National Center for Technologies in Education\n"
    "🏛️ center national de technologie en education\n"
    "🏛️ المركز الوطني لتكنولوجيات في التربية CNTE\n"
    "\n✳️ أرسل أي أمر أو سؤال للبدء..."
)

COMMANDS = {
    "genpass": " Generated password: {}",
    "uuid": " UUID: {}",
    "time": " Current time: {}",
    "json": " JSON Parsed: {}",
    "b64encode": " Base64 Encoded: {}",
    "b64decode": " Base64 Decoded: {}",
    "hash": " Hashed (SHA256): {}",
    "ip": " Valid IP: {}",

    "urlscan": " URL Scan submitted! UUID: {}\nيمكنك التحقق لاحقًا عبر urlscan.io",
    "emailcheck": " Email valid: {}",
    "useragent": " Example User-Agent: {}",
    "whois": " WHOIS info:\n{}",
    "dnslookup": " DNS Lookup (A record): {}",
    "encodehex": " Hex Encoded: {}",
    "decodehex": " Hex Decoded: {}",
    "portcheck": " Port {} on {} is: {}",
    "passwordstrength": " Password strength: {}",
    "headersinfo": " Common HTTP headers:\n{}",
    "ping": " Ping result:\n{}",
    "whoami": " User info:\n{}",
}

QUESTIONS = {
    "ما هو التصيد الاحتيالي؟": " التصيد الاحتيالي هو محاولة لسرقة المعلومات الحساسة عبر الخداع.",
    "ما هو الفيروس؟": " الفيروس هو برنامج ضار ينتشر بين الأجهزة ويؤثر على البيانات.",
    "ما هو جدار الحماية؟": " جدار الحماية هو أداة لحماية الشبكة من الدخول غير المصرح به.",
    "qu’est-ce que le phishing ?": " Le phishing est une tentative de voler des informations sensibles par tromperie.",
    "c’est quoi un firewall ?": " Un pare-feu est un dispositif de sécurité réseau qui contrôle le trafic.",
    "what is phishing?": " Phishing is an attempt to steal sensitive information by deception.",
}

SMART_BRAIN_KB = {
    # عربي
    "bot": "by Rayen mkadmini",
    "Oussama": "the best",
    "Ryan": "the best",
    "what is the best way to learn python?": "There are many ways to learn Python",
    "kess7": "I'M rayen mkadmini hahaha",
    "تحديث": " تحديث برامجك ونظام التشغيل يقلل من ثغرات الأمان.",
    "CNTE": " CNTE هو المركز الوطني لتكنولوجيا التربية، يهدف إلى دعم التعليم من خلال التكنولوجيا في تونس",
    "instagrame": "@el__rou__2007",
    "facebook": "Mkadmini Rayen",
    "whatsApp": "+216 20653322",
    "aziz": "lm3alem s8ayer",
    "Youth": "My home",
    "فيروس": " احرص على تثبيت مضاد فيروسات محدث لفحص جهازك بانتظام.",
    "كلمة السر": " استخدم كلمات سر قوية وفريدة لكل حساب.",
    "تصيد": " التصيد الاحتيالي محاولة لخداعك لكشف بياناتك الشخصية.",
    "هاكر": " الهاكر هو من يحاول اختراق الأنظمة لأسباب مختلفة.",
    "تشفير": " التشفير يحمي البيانات بجعلها غير قابلة للقراءة بدون مفتاح صحيح.",
    "merci": "derien",
    "شكرا": "لا شكر على واجب",
    "برمجيات خبيثة": " البرمجيات الخبيثة (Malware) تهدف لإلحاق الضرر بالأجهزة والبيانات.",
    "جدار حماية": " جدار الحماية يمنع الدخول غير المصرح به إلى شبكتك.",
    "هجوم رفض الخدمة": " هجوم DDoS يهدف إلى تعطيل الخدمة عبر إغراق الخادم بطلبات مزيفة.",
    "نسخة احتياطية": " نسخ البيانات احتياطياً يحميك من فقدان المعلومات عند الهجمات.",
    "ثغرة أمنية": " الثغرات الأمنية تسمح للمهاجمين باستغلال نقاط ضعف النظام.",
    "تصيد احتيالي": " التصيد محاولة خداع المستخدمين للحصول على معلوماتهم الشخصية.",
    "اختراق": " الاختراق يعني الوصول غير المصرح به إلى الأنظمة أو البيانات.",
    "تحديثات الأمان": " تحديثات الأمان مهمة لسد الثغرات وحماية النظام.",

    # français
    "vpn": "Utilisez un VPN pour sécuriser votre connexion, surtout sur les réseaux publics.",
    "mise à jour": " Mettre à jour vos logiciels réduit les failles de sécurité.",
    "virus": " Installez un antivirus à jour pour protéger votre appareil.",
    "mot de passe": " Utilisez des mots de passe forts et uniques pour chaque compte.",
    "phishing": " Le phishing est une tentative de tromperie pour voler vos données.",
    "hacker": " Un hacker essaie de pénétrer des systèmes pour diverses raisons.",
    "cryptage": " Le cryptage protège les données en les rendant illisibles sans la clé.",
    "malware": " Les malwares visent à endommager les appareils et les données.",
    "pare-feu":  "Un pare-feu bloque les accès non autorisés à votre réseau.",
    "attaque par déni de service": " Une attaque DDoS vise à rendre un service indisponible.",
    "sauvegarde": " Faire des sauvegardes protège contre la perte de données.",
    "vulnérabilité": " Les vulnérabilités sont des failles que les attaquants peuvent exploiter.",
    "hameçonnage": " Le phishing tente de tromper les utilisateurs pour voler leurs données.",
    "piratage": " Le piratage est un accès non autorisé aux systèmes.",
    "mises à jour de sécurité": " Les mises à jour corrigent les failles et protègent le système.",

    # English
    "vpn": " Use a VPN to secure your connection, especially on public networks.",
    "update": " Keeping your software up-to-date reduces security vulnerabilities.",
    "virus": " Install an updated antivirus to protect your device.",
    "password": " Use strong and unique passwords for every account.",
    "phishing": " Phishing is a deceptive attempt to steal your personal data.",
    "hacker": " A hacker tries to breach systems for various reasons.",
    "encryption": " Encryption protects data by making it unreadable without the key.",
    "malware": " Malware aims to damage devices and steal data.",
    "firewall": " A firewall blocks unauthorized access to your network.",
    "denial of service": " A DDoS attack aims to make a service unavailable.",
    "backup": " Backups protect your data against loss.",
    "vulnerability": " Vulnerabilities are weaknesses attackers can exploit.",
    "phishing": " Phishing tricks users into giving away personal data.",
    "hacking": " Hacking is unauthorized access to systems.",
    "security updates": " Security updates patch vulnerabilities and protect systems.",
}

def generate_password(length=12):
    return ''.join(secrets.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(length))

def get_closest_command(user_input):
    commands = list(COMMANDS.keys())
    result = process.extractOne(user_input, commands, scorer=fuzz.WRatio)
    if result:
        command, score, *_ = result
        if score >= 70:
            return command
    return None

def find_question(user_input):
    questions = list(QUESTIONS.keys())
    result = process.extractOne(user_input, questions, scorer=fuzz.WRatio)
    if result:
        question, score, *_ = result
        if score >= 70:
            return QUESTIONS[question]
    return None

def smart_brain(user_input):
    for keyword, response in SMART_BRAIN_KB.items():
        if keyword.lower() in user_input.lower():
            return response
    return None

def is_valid_email(email):
    regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(regex, email) is not None

def check_password_strength(password):
    length = len(password)
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    score = sum([has_upper, has_lower, has_digit, has_special])
    if length >= 12 and score == 4:
        return "Strong"
    elif length >= 8 and score >= 3:
        return "Medium"
    else:
        return "Weak"

async def reply_with_text_and_voice(text: str, update: Update, lang="ar"):
    await update.message.reply_text(text)
    try:
        tts = gTTS(text, lang=lang)
        audio_file = "reply.mp3"
        tts.save(audio_file)
        with open(audio_file, 'rb') as f:
            await update.message.reply_voice(f)
        os.remove(audio_file)
    except Exception as e:
        print(f"Error in TTS: {e}")
        await update.message.reply_text("⚠️ تعذر توليد الرد الصوتي.")

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(WELCOME_MESSAGE)
    user = update.effective_user
    register_user(user.id, user.username or "N/A", user.full_name or "N/A")


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    insert_user(update.effective_user)
    log_command(update.effective_user.id, update.message.text)
    user = update.effective_user
    register_user(user.id, user.username or "N/A", user.full_name or "N/A")

    text = update.message.text.strip()
    print(f"📩 Received message: {text}")

    cmd_input = text.lower().split()[0]
    args = ' '.join(text.split()[1:])
    matched = get_closest_command(cmd_input)

    if matched == "genpass":
        await update.message.reply_text(COMMANDS["genpass"].format(generate_password()))
    elif matched == "uuid":
        await update.message.reply_text(COMMANDS["uuid"].format(str(uuid.uuid4())))
    elif matched == "time":
        await update.message.reply_text(COMMANDS["time"].format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    elif matched == "json":
        try:
            obj = json.loads(args)
            await update.message.reply_text(COMMANDS["json"].format(json.dumps(obj, indent=2, ensure_ascii=False)))
        except:
            await update.message.reply_text("⚠️ JSON غير صالح.")
    elif matched == "b64encode":
        encoded = base64.b64encode(args.encode()).decode()
        await update.message.reply_text(COMMANDS["b64encode"].format(encoded))
    elif matched == "b64decode":
        try:
            decoded = base64.b64decode(args).decode()
            await update.message.reply_text(COMMANDS["b64decode"].format(decoded))
        except:
            await update.message.reply_text("⚠️ Base64 غير صالح.")
    elif matched == "hash":
        hashed = hashlib.sha256(args.encode()).hexdigest()
        await update.message.reply_text(COMMANDS["hash"].format(hashed))
    elif matched == "ip":
        try:
            ip = ipaddress.ip_address(args)
            await update.message.reply_text(COMMANDS["ip"].format(str(ip)))
        except:
            await update.message.reply_text("⚠️ عنوان IP غير صالح.")

    elif matched == "urlscan":
        if not args.startswith("http"):
            await update.message.reply_text("⚠️ الرجاء إرسال رابط يبدأ بـ http أو https.")
            return
        try:
            headers = {'API-Key': '01986c3c-f3c0-744b-9454-5966f263f1be'}  # ضع مفتاح API الخاص بك هنا إذا كان لديك
            data = {"url": args, "visibility": "public"}
            r = requests.post("https://urlscan.io/api/v1/scan/", json=data, headers=headers)
            if r.status_code == 200:
                json_data = r.json()
                await update.message.reply_text(COMMANDS["urlscan"].format(json_data.get('uuid', '')))
            else:
                await update.message.reply_text("⚠️ فشل في إرسال الطلب للـ URL Scan.")
        except Exception as e:
            await update.message.reply_text(f"⚠️ خطأ: {e}")

    elif matched == "emailcheck":
        valid = is_valid_email(args)
        await update.message.reply_text(COMMANDS["emailcheck"].format("Valid" if valid else "Invalid"))
    elif matched == "useragent":
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
        await update.message.reply_text(COMMANDS["useragent"].format(ua))
    elif matched == "whois":
        try:
            w = whois.whois(args)
            text = json.dumps(w, default=str, indent=2, ensure_ascii=False)
            await update.message.reply_text(COMMANDS["whois"].format(text))
        except Exception as e:
            await update.message.reply_text(f"⚠️ خطأ في Whois: {e}")
    elif matched == "dnslookup":
        try:
            records = socket.gethostbyname(args)
            await update.message.reply_text(COMMANDS["dnslookup"].format(records))
        except Exception as e:
            await update.message.reply_text(f"⚠️ DNS Lookup failed: {e}")
    elif matched == "encodehex":
        encoded = args.encode().hex()
        await update.message.reply_text(COMMANDS["encodehex"].format(encoded))
    elif matched == "decodehex":
        try:
            decoded = bytes.fromhex(args).decode()
            await update.message.reply_text(COMMANDS["decodehex"].format(decoded))
        except:
            await update.message.reply_text("⚠️ Hex غير صالح.")
    elif matched == "portcheck":
        parts = args.split()
        if len(parts) == 2:
            host, port_str = parts
            try:
                port = int(port_str)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                sock.close()
                status = "Open" if result == 0 else "Closed"
                await update.message.reply_text(COMMANDS["portcheck"].format(port, host, status))
            except:
                await update.message.reply_text("⚠️ رقم بورت غير صالح.")
        else:
            await update.message.reply_text("⚠️ استخدم: portcheck [host] [port]")
    elif matched == "passwordstrength":
        strength = check_password_strength(args)
        await update.message.reply_text(COMMANDS["passwordstrength"].format(strength))
    elif matched == "headersinfo":
        common_headers = "User-Agent, Accept, Content-Type, Authorization"
        await update.message.reply_text(COMMANDS["headersinfo"].format(common_headers))
    elif matched == "ping":
        host = args if args else "google.com"
        param = "-n" if platform.system().lower()=="windows" else "-c"
        command = ["ping", param, "1", host]
        try:
            output = subprocess.check_output(command).decode()
            await update.message.reply_text(COMMANDS["ping"].format(output))
        except Exception as e:
            await update.message.reply_text(COMMANDS["ping"].format(f"Failed: {e}"))
    elif matched == "whoami":
        user = update.effective_user
        info = f"ID: {user.id}\nUsername: @{user.username}\nName: {user.full_name}"
        await update.message.reply_text(COMMANDS["whoami"].format(info))
    else:
        answer = find_question(text)
        if answer:
            await reply_with_text_and_voice(answer, update)
        else:
            smart_response = smart_brain(text)
            if smart_response:
                await reply_with_text_and_voice(smart_response, update)
            else:
                await update.message.reply_text("❓ لم أفهم الأمر. أو اطرح سؤالًا حول الأمن السيبراني.")

async def handle_voice(update: Update, context: ContextTypes.DEFAULT_TYPE):
    file = await update.message.voice.get_file()
    file_path = await file.download_to_drive()

    wav_path = file_path.replace(".oga", ".wav")
    sound = AudioSegment.from_file(file_path)
    sound.export(wav_path, format="wav")

    recognizer = sr.Recognizer()
    with sr.AudioFile(wav_path) as source:
        audio = recognizer.record(source)

    try:
        text = recognizer.recognize_google(audio, language="ar-TN")
        await update.message.reply_text(f"🗣️ النص المحول: {text}")
        update.message.text = text
        await handle_message(update, context)
    except sr.UnknownValueError:
        await update.message.reply_text("❌ لم أستطع فهم الصوت.")
    except sr.RequestError as e:
        await update.message.reply_text(f"⚠️ خطأ في خدمة التعرف على الصوت: {e}")
    finally:
        try:
            os.remove(file_path)
            if os.path.exists(wav_path):
                os.remove(wav_path)
        except Exception as e:
            print(f"Error cleaning files: {e}")

if __name__ == "__main__":
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), handle_message))
    app.add_handler(MessageHandler(filters.VOICE, handle_voice))
    print("✅ BOT IS CONNECTED")
    app.run_polling()
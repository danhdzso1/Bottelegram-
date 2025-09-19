import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton, ReplyKeyboardMarkup, KeyboardButton
import os, subprocess, threading, sys

TOKEN = "8421788347:AAF7FIESPp2eChp0o03lfG9lFjjvL0Xx4n8"
bot = telebot.TeleBot(TOKEN)

ADMIN_IDS = [7244630619]
bot_locked = False
processes = {}  # {user_id: {filename: {"process": proc, "logs": ""}}}

# ================== TIỆN ÍCH ==================
os.makedirs("user_files", exist_ok=True)

def ensure_user_dir(user_id):
    user_dir = f"user_files/{user_id}"
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

def list_user_files(user_id):
    user_dir = ensure_user_dir(user_id)
    return [f for f in os.listdir(user_dir) if os.path.isfile(os.path.join(user_dir, f))]

def check_lock(user_id):
    return bot_locked and user_id not in ADMIN_IDS

# ================== SUBPROCESS LOG THREAD ==================
def run_file(user_id, filename, file_path):
    proc = subprocess.Popen([sys.executable, file_path],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, bufsize=1)

    if user_id not in processes:
        processes[user_id] = {}
    processes[user_id][filename] = {"process": proc, "logs": ""}

    def read_output():
        try:
            for line in proc.stdout:
                processes[user_id][filename]["logs"] += line
            for line in proc.stderr:
                processes[user_id][filename]["logs"] += line
        except:
            pass

    t = threading.Thread(target=read_output, daemon=True)
    t.start()
    proc.wait()
    t.join()

# ================== SHOW USER FILES ==================
def show_user_files(chat_id, user_id):
    user_dir = ensure_user_dir(user_id)
    files = list_user_files(user_id)

    if not files:
        bot.send_message(chat_id, "📭 Bạn chưa upload file nào.")
        return

    for f in files:
        kb = InlineKeyboardMarkup(row_width=2)
        kb.add(
            InlineKeyboardButton("▶️ Start", callback_data=f"{user_id}:start:{f}"),
            InlineKeyboardButton("🛑 Stop", callback_data=f"{user_id}:stop:{f}"),
        )
        kb.add(
            InlineKeyboardButton("🔄 Restart", callback_data=f"{user_id}:restart:{f}"),
            InlineKeyboardButton("🗑 Delete", callback_data=f"{user_id}:delete:{f}")
        )
        kb.add(InlineKeyboardButton("📜 Logs", callback_data=f"{user_id}:logs:{f}"))

        status = "🟢 Running" if user_id in processes and f in processes[user_id] else "🔴 Stopped"
        bot.send_message(chat_id, f"⚙️ File: `{f}`\nStatus: {status}", parse_mode="Markdown", reply_markup=kb)

# ================== START ==================
@bot.message_handler(commands=['start'])
def send_welcome(message):
    if check_lock(message.from_user.id):
        bot.send_message(message.chat.id, "⚠️ Bot hiện đang bị khóa.")
        return

    user_id = message.from_user.id
    user_name = message.from_user.first_name or "Không có tên"
    user_username = "@" + message.from_user.username if message.from_user.username else "Không có username"
    status_user = "🆓 Free User" if user_id not in ADMIN_IDS else "👑 Admin"
    status_bot = "🔓 Unlocked" if not bot_locked else "🔒 Locked"

    welcome_text = f"""
Your Status: {status_user} | Bot Status: {status_bot}

Welcome, {user_name}!
🆔 Your ID: {user_id}
♻️ Username: {user_username}

〽️ Bot được tạo bởi @cdanhdev ♻️
"""

    kb = ReplyKeyboardMarkup(resize_keyboard=True)
    kb.add(KeyboardButton("📤 Upload File"), KeyboardButton("📁 Check Files"))
    kb.add(KeyboardButton("⚡ Bot Speed"), KeyboardButton("📊 Statistics"))
    kb.add(KeyboardButton("📞 Contact Owner"))

    bot.send_message(message.chat.id, welcome_text, reply_markup=kb)

# ================== LOCK / UNLOCK ==================
@bot.message_handler(commands=['lock'])
def lock_bot(message):
    global bot_locked
    if message.from_user.id in ADMIN_IDS:
        bot_locked = True
        bot.send_message(message.chat.id, "🔒 Bot đã bị khóa. Chỉ Admin mới dùng được.")
    else:
        bot.send_message(message.chat.id, "⛔ Bạn không có quyền khóa bot.")

@bot.message_handler(commands=['unlock'])
def unlock_bot(message):
    global bot_locked
    if message.from_user.id in ADMIN_IDS:
        bot_locked = False
        bot.send_message(message.chat.id, "🔓 Bot đã được mở. Mọi người có thể dùng.")
    else:
        bot.send_message(message.chat.id, "⛔ Bạn không có quyền mở bot.")

# ================== FILE UPLOAD ==================
@bot.message_handler(content_types=['document'])
def handle_file_upload(message):
    user_id = message.from_user.id

    if check_lock(user_id):
        bot.send_message(message.chat.id, "⚠️ Bot đang bị khóa.")
        return

    bot.send_chat_action(message.chat.id, "typing")

    file_info = bot.get_file(message.document.file_id)
    file_name = message.document.file_name

    if not file_name.endswith(".py"):
        bot.send_message(message.chat.id, "⚠️ Chỉ chấp nhận file .py")
        return

    user_dir = ensure_user_dir(user_id)
    file_path = os.path.join(user_dir, file_name)

    downloaded_file = bot.download_file(file_info.file_path)
    with open(file_path, "wb") as f:
        f.write(downloaded_file)

    if user_id in processes and file_name in processes[user_id]:
        try: processes[user_id][file_name]["process"].terminate()
        except: pass
        del processes[user_id][file_name]

    bot.send_message(message.chat.id, f"📥 Đã lưu file `{file_name}`", parse_mode="Markdown")
    threading.Thread(target=run_file, args=(user_id, file_name, file_path), daemon=True).start()
    bot.send_message(message.chat.id, f"🚀 File `{file_name}` đã được chạy.", parse_mode="Markdown")

# ================== MENU BUTTONS ==================
@bot.message_handler(func=lambda m: True)
def handle_reply_buttons(message):
    user_id = message.from_user.id
    text = message.text

    if text == "📤 Upload File":
        if bot_locked:
            bot.send_message(message.chat.id, "⚠️ Bot đang bị khóa, không thể upload file.")
            return
        bot.send_message(message.chat.id, "📤 Gửi file .py bạn muốn upload.")

    elif text == "📁 Check Files":
        if bot_locked:
            bot.send_message(message.chat.id, "⚠️ Bot đang bị khóa, không thể thao tác file.")
            return
        show_user_files(message.chat.id, user_id)

    elif text == "⚡ Bot Speed":
        bot.send_message(message.chat.id, "⚡ Bot đang chạy mượt!")

    elif text == "📊 Statistics":
        total_users = len(os.listdir("user_files"))
        total_files = sum(len(list_user_files(int(uid))) for uid in os.listdir("user_files"))
        bot.send_message(
            message.chat.id,
            f"<b>📊 Statistics</b>\n\n📂 Uploaded files: {total_files}\n👤 Total users: {total_users}",
            parse_mode="HTML"
        )

    elif text == "📞 Contact Owner":
        contact_text = "<b>📞 Liên hệ Owner</b>"
        markup = InlineKeyboardMarkup()
        markup.add(InlineKeyboardButton("💥 Admin", url="https://t.me/cdanhdev"))
        bot.send_message(message.chat.id, contact_text, parse_mode="HTML", reply_markup=markup)

    else:
        bot.send_message(message.chat.id, "⚠️ Lệnh không hợp lệ, hãy chọn bằng nút bàn phím.")

# ================== INLINE FILE ACTIONS ==================
@bot.callback_query_handler(func=lambda call: True)
def callback_query(call):
    try:
        parts = call.data.split(":", 2)
        if len(parts) < 2:
            return
        user_id = int(parts[0])
        action = parts[1]
        filename = parts[2] if len(parts) == 3 else None

        if bot_locked:
            bot.answer_callback_query(call.id, "⚠️ Bot đang bị khóa, không thể thao tác file.")
            return

        if user_id != call.from_user.id and call.from_user.id not in ADMIN_IDS:
            bot.answer_callback_query(call.id, "⚠️ Không thể thao tác file của người khác.")
            return

        user_dir = ensure_user_dir(user_id)
        file_path = os.path.join(user_dir, filename) if filename else None

        if user_id not in processes:
            processes[user_id] = {}
        user_processes = processes[user_id]

        if action == "start" and filename:
            if filename not in user_processes:
                threading.Thread(target=run_file, args=(user_id, filename, file_path), daemon=True).start()
            show_user_files(call.message.chat.id, user_id)

        elif action == "stop" and filename:
            if filename in user_processes:
                try: user_processes[filename]["process"].terminate()
                except: pass
                del user_processes[filename]
            show_user_files(call.message.chat.id, user_id)

        elif action == "restart" and filename:
            if filename in user_processes:
                try: user_processes[filename]["process"].terminate()
                except: pass
                del user_processes[filename]
            threading.Thread(target=run_file, args=(user_id, filename, file_path), daemon=True).start()
            show_user_files(call.message.chat.id, user_id)

        elif action == "delete" and filename:
            if filename in user_processes:
                try: user_processes[filename]["process"].terminate()
                except: pass
                del user_processes[filename]
            if os.path.exists(file_path):
                os.remove(file_path)
            show_user_files(call.message.chat.id, user_id)

        elif action == "logs" and filename:
            logs = user_processes.get(filename, {}).get("logs", "📭 Không có log.")
            if len(logs) > 4000:
                logs = logs[-4000:]
            bot.send_message(call.message.chat.id, f"📜 Logs của `{filename}`:\n\n```\n{logs}\n```",
                             parse_mode="Markdown")
    except Exception as e:
        print("Callback error:", e)

# ================== RUN BOT ==================
print("🤖 Bot đang chạy...")
bot.infinity_polling(timeout=60)
import telebot
import subprocess
import sys
from requests import post, Session
import time
import datetime
import threading
from urllib.parse import urlparse
import psutil
import tempfile
import random
from gtts import gTTS
import re
import string
import os
from threading import Lock
import requests
import sqlite3
from telebot import types
from time import strftime
import queue
import pytz
admin_diggory = "Congdanh208" 
name_bot = "DanhvipzZz"
zalo = "0337843824"
web = "https://dichvukey.site/"
facebook = "no"
#allowed_group_id = -1002407089817
allowed_group_id = [-1002407089817, -1002201340697]
bot=telebot.TeleBot("7446036510:AAEjcUkfnGW7usLTuDz4xvWUSQyF7ZWqJto") 
#real :AAEPdyxq7Hq1YQHEVG_NPyfWtt8eT1Ibpe8
#phu 7602622138:AAEY_M2FDQd1JuAI7z05MBvcvW7QDfZ86V0
print("Bot đã được khởi động thành công")
users_keys = {}
key = ""
user_cooldown = {}
share_log = []
auto_spam_active = False
last_sms_time = {}
global_lock = Lock()
allowed_users = []
processes = []
ADMIN_ID =  7244630619
connection = sqlite3.connect('user_data.db')
cursor = connection.cursor()
last_command_time = {}
VIP_COOLDOWN_TIMEGG = 5  
FREE_COOLDOWN_TIMEGG = 10  
last_command_timegg = 0

def check_command_cooldown(user_id, command, cooldown):
    current_time = time.time()
    
    if user_id in last_command_time and current_time - last_command_time[user_id].get(command, 0) < cooldown:
        remaining_time = int(cooldown - (current_time - last_command_time[user_id].get(command, 0)))
        return remaining_time
    else:
        last_command_time.setdefault(user_id, {})[command] = current_time
        return None

cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY,
        expiration_time TEXT
    )
''')
connection.commit()

def TimeStamp():
  now = str(datetime.date.today())
  return now


def load_users_from_database():
  cursor.execute('SELECT user_id, expiration_time FROM users')
  rows = cursor.fetchall()
  for row in rows:
    user_id = row[0]
    expiration_time = datetime.datetime.strptime(row[1], '%Y-%m-%d %H:%M:%S')
    if expiration_time > datetime.datetime.now():
      allowed_users.append(user_id)


def save_user_to_database(connection, user_id, expiration_time):
  cursor = connection.cursor()
  cursor.execute(
    '''
        INSERT OR REPLACE INTO users (user_id, expiration_time)
        VALUES (?, ?)
    ''', (user_id, expiration_time.strftime('%Y-%m-%d %H:%M:%S')))
  connection.commit()
###

vietnam_tz = pytz.timezone('Asia/Ho_Chi_Minh')


###

####
start_time = time.time()

@bot.message_handler(commands=['muavip'])
def muavip(message):
    user = message.from_user

    if message.chat.type != "private":
        bot.send_message(message.chat.id, "Vui lòng nhắn riêng với bot để thực hiện lệnh này.\nBảng giá: 1 ngày VIP = 1,000 VND, tối đa 100 ngày = 100,000 VND.")
        return

    cooldown = check_command_cooldown(user.id, '/muavip', 5)  
    if cooldown:
        bot.send_message(message.chat.id, f"Vui lòng chờ {cooldown} giây trước khi thực hiện lại lệnh này.")
        return

    try:
        so_tien = int(message.text.split()[1])

        if so_tien < 5000 or so_tien > 100000 or so_tien % 1000 != 0:
            bot.send_message(message.chat.id, "Số tiền không hợp lệ. Mỗi 1,000 VND tương ứng với 1 ngày VIP. Vui lòng nhập số tiền từ 5,000 đến 100,000 VND.")
            return

        full_name = user.first_name if user.first_name else "user"
        letters = ''.join(random.choices(string.ascii_uppercase, k=5))
        digits = ''.join(random.choices(string.digits, k=7))
        random_str = letters + digits
        noidung = f"{full_name} {random_str}"

        message_text = (f"STK: `đang cập nhật...`\n"
                        f"Ngân hàng: `MBBANK`\n"
                        f"Chủ tài khoản: `Cong Danh`\n\n"
                        f"Vui lòng nạp {so_tien} VNĐ theo đúng nội dung\n"
                        f"Nội Dung: `{noidung}`\n"
                        f"Sau khi nạp hãy nhấn Xác Nhận\n")

        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton("Xác Nhận ✅", callback_data=f"vip:confirm_{so_tien}_{noidung}_{user.id}"))
        markup.add(types.InlineKeyboardButton("Huỷ Bỏ ❌", callback_data=f"vip:cancel_{user.id}"))

        bot.send_message(message.chat.id, message_text, reply_markup=markup, parse_mode='Markdown')

    except (IndexError, ValueError):
        bot.send_message(message.chat.id, "Vui lòng nhập số tiền cần nạp | Ví dụ: /muavip 100000")

@bot.callback_query_handler(func=lambda call: True)
def callback_query(call):
    data = call.data
    args = data.split("_")

    if args[0] == "vip:confirm":
        so_tien, noidung, user_id = args[1:]
        admin_message = (f"Người mua VIP: {call.from_user.first_name} (ID: {user_id})\n"
                         f"Số tiền: {so_tien} VNĐ\n"
                         f"Nội dung: {noidung}\n"
                         f"Thời gian nạp: {datetime.datetime.now(vietnam_tz).strftime('%H:%M:%S %d-%m-%Y')}")
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton("Duyệt ✅", callback_data=f"vip:approve_{user_id}_{so_tien}"))
        markup.add(types.InlineKeyboardButton("Từ Chối ❌", callback_data=f"vip:deny_{user_id}_{so_tien}"))

        bot.send_message(chat_id=7841142966, text=admin_message, reply_markup=markup)
        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                              text=f"Yêu cầu mua VIP đã được gửi đến quản trị viên 📤\nSố tiền: {so_tien} VNĐ\nNội dung: {noidung}\nNgày tạo đơn: {datetime.datetime.now(vietnam_tz).strftime('%H:%M:%S %d-%m-%Y')}")

    elif args[0] == "vip:cancel":
        user_id = args[1]
        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text="Bạn đã huỷ bỏ yêu cầu mua VIP.")
        bot.delete_message(chat_id=call.message.chat.id, message_id=call.message.message_id)

    elif args[0] == "vip:approve":
        user_id, so_tien = args[1:]
        so_ngay_vip = int(so_tien) // 1000
        so_ngay_vip = min(so_ngay_vip, 100)  
        expiration_time = datetime.datetime.now() + datetime.timedelta(days=so_ngay_vip)

        connection = sqlite3.connect('user_data.db')
        save_user_to_database(connection, int(user_id), expiration_time)
        connection.close()

        allowed_users.append(int(user_id))

        bot.send_message(chat_id=user_id, text=f"Chúc mừng! Bạn đã trở thành VIP trong {so_ngay_vip} ngày đến {expiration_time.strftime('%Y-%m-%d %H:%M:%S')}.")
        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=f"Đã duyệt yêu cầu VIP của ID {user_id}.")
        bot.delete_message(chat_id=call.message.chat.id, message_id=call.message.message_id)

    elif args[0] == "vip:deny":
        user_id, so_tien = args[1:]
        bot.send_message(chat_id=user_id, text="Yêu cầu VIP của bạn đã bị từ chối.")
        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=f"Đã từ chối yêu cầu VIP của ID {user_id}.")
        bot.delete_message(chat_id=call.message.chat.id, message_id=call.message.message_id)

load_users_from_database()

    ##






# Khởi động bot





def fetch_tiktok_data(url):
    api_url = f'https://www.tikwm.com/api?url={url}'
    try:
        response = requests.get(api_url)
        response.raise_for_status()  
        data = response.json()
        return data
    except requests.exceptions.RequestException as e:
        print(f"Error fetching TikTok data: {e}")
        return None

@bot.message_handler(commands=['tiktok'])
def tiktok_command(message):
    command_parts = message.text.split(maxsplit=1)
    if len(command_parts) == 2:
        url = command_parts[1].strip()
        data = fetch_tiktok_data(url)
        
        if data and 'code' in data and data['code'] == 0:
            video_title = data['data'].get('title', 'N/A')
            video_url = data['data'].get('play', 'N/A')
            music_title = data['data']['music_info'].get('title', 'N/A')
            music_url = data['data']['music_info'].get('play', 'N/A')
            
            reply_message = f'<blockquote>Tiêu đề Video: {video_title}\n──────────────────\nĐường dẫn Video: <a href="{video_url}">TẠI ĐÂY</a>\n──────────────────\nTiêu đề Nhạc: {music_title}\nĐường dẫn Nhạc: <a href="{music_url}">Link</a></blockquote>'
            bot.reply_to(message, reply_message, parse_mode='HTML')
        else:
            bot.reply_to(message, "Không thể lấy dữ liệu từ TikTok.")
    else:
        bot.reply_to(message, "Sai Link.")


@bot.message_handler(commands=['tool'])
def send_tool_links(message):
    tool_links = [
        ("https://www.mediafire.com/file/9xug4wkya10c32s/gopvip.py/file", "Tool gộp vip nhiều chế độ"),
        ("https://dichvukey.site", "Tool Gộp - Source Tool Vip")
    ]
    
    markup = types.InlineKeyboardMarkup()
    for link, desc in tool_links:
        button = types.InlineKeyboardButton(text=desc, url=link)
        markup.add(button)
    
    bot.send_message(message.chat.id, "Nhấp Vào Để Tải :", reply_markup=markup)
####
#####
video_url = 'https://v16m-default.akamaized.net/b7650db4ac7f717b7be6bd6a04777a0d/66a418a5/video/tos/useast2a/tos-useast2a-ve-0068-euttp/o4QTIgGIrNbkAPGKKLKteXyLedLE7IEgeSzeE2/?a=0&bti=OTg7QGo5QHM6OjZALTAzYCMvcCMxNDNg&ch=0&cr=0&dr=0&lr=all&cd=0%7C0%7C0%7C0&cv=1&br=2576&bt=1288&cs=0&ds=6&ft=XE5bCqT0majPD12cy-773wUOx5EcMeF~O5&mime_type=video_mp4&qs=0&rc=Mzk1OzY7PGdpZjxkOTQ3M0Bpajh1O2w5cmlzbzMzZjgzM0AuNWJgLi02NjMxLzBgXjUyYSNzNmptMmRjazFgLS1kL2Nzcw%3D%3D&vvpl=1&l=202407261543513F37EAD38E23B6263167&btag=e00088000'
@bot.message_handler(commands=['add', 'adduser'])
def add_user(message):
    admin_id = message.from_user.id
    if admin_id != ADMIN_ID:
        bot.reply_to(message, 'Bạn Không Phải admin')
        return

    if len(message.text.split()) == 1:
        bot.reply_to(message, 'VUI LÒNG NHẬP ID NGƯỜI DÙNG VÀ SỐ NGÀY')
        return
    if len(message.text.split()) == 2:
        bot.reply_to(message, 'HÃY NHẬP SỐ NGÀY')
        return
    user_id = int(message.text.split()[1])
    allowed_users.append(user_id)
    days = int(message.text.split()[2])
    expiration_time = datetime.datetime.now() + datetime.timedelta(days)
    connection = sqlite3.connect('user_data.db')
    save_user_to_database(connection, user_id, expiration_time)
    connection.close()

    caption_text = (f'<blockquote>NGƯỜI DÙNG CÓ ID {user_id}\nĐÃ ĐƯỢC THÊM VÀO DANH SÁCH VIP\nTHỜI GIAN: {days} DAY\nLỆNH CÓ THỂ SỬ DỤNG CÁC LỆNH TRONG [/help]</blockquote>')
    bot.send_video(
        message.chat.id,
        video_url,
        caption=caption_text, parse_mode='HTML')

load_users_from_database()

def is_key_approved(chat_id, key):
    if chat_id in users_keys:
        user_key, timestamp = users_keys[chat_id]
        if user_key == key:
            current_time = datetime.datetime.now()
            if current_time - timestamp <= datetime.timedelta(hours=2):
                return True
            else:
                del users_keys[chat_id]
    return False




@bot.message_handler(commands=['help'])
def send_help(message):
    bot.reply_to(message, """<blockquote>
╔════════════════╗  
    📌 *DANH SÁCH LỆNH*
╚════════════════╝  
/help       Full Lệnh  
/spam        Spam SĐT  
/spamvip     Spam SĐT VIP  
/gg          Tìm Ảnh GG  
/info        Check FB  
/tik         INFO TikTok  
/tele        INFO Telegram  
/thoitiet    Check Thời Tiết  
/hoi         Hỏi GG Trả Lời  
/id          ID Telegram  
/voice       Chữ Thành Giọng  
/tool        Tool Gộp  
/tai         Tải File Bằng Link  
/code        Lấy HTML Web  
/tv          Ngôn Ngữ Tiếng Việt  
/video  XEM VD GÁI XINH
/muavip  Mua Vip Đỡ Vượt Key
╔═════════════════╗  
       🔥 *FREE FIRE* 🔥  
╚═════════════════╝  
/ff   CHECK TT BẰNG ID
/like     BUFF LIKE 
/name CHECK TT BẰNG TÊN
/visit    BUFF VIEW
/ngl    SPAM nglink
╔════════════╗  
           TIKTOK  
╚════════════╝  
/tiktok      Tải Video TikTok  
/viewtiktok  Xem View  
/fl   BUFF FOLLOW
Mua FOLLOW MXH TẠI : https://dvmangxahoiuytin.site/home/
</blockquote>""", parse_mode='HTML')



###freespam



        
processes = []
last_spam_time = {}

def TimeStamp():
    return datetime.datetime.now().strftime("%Y-%m-%d")

@bot.message_handler(commands=['getkey'])
def startkey(message):
    user_id = message.from_user.id
    today_day = datetime.date.today().day
    key = "danh" + str(user_id * today_day - 20207)

    api_token = '64f857ff1b02a144e1073c7e'
    key_url = f"https://dichvukey.site/key.html?key={key}"

    try:
        response = requests.get(f'https://link4m.co/api-shorten/v2?api={api_token}&url={key_url}')
        response.raise_for_status()
        url_data = response.json()
        print(key)

        if 'shortenedUrl' in url_data:
            url_key = url_data['shortenedUrl']
            text = (f'Link Lấy Key Ngày {TimeStamp()} LÀ: {url_key}\n'
                    'KHI LẤY KEY XONG, DÙNG LỆNH /key DanhzZzXxx ĐỂ TIẾP TỤC Hoặc /muavip đỡ vượt tốn thời gian nhé')
            bot.reply_to(message, text)
        else:
            bot.reply_to(message, 'Lỗi.')
    except requests.RequestException:
        bot.reply_to(message, 'Lỗi.')


@bot.message_handler(commands=['key'])
def key(message):
    if len(message.text.split()) != 2:
        bot.reply_to(message, 'Key Đã Vượt Là? đã vượt thì nhập /key chưa vượt thì /getkey và /muavip nhé')
        return

    user_id = message.from_user.id
    key = message.text.split()[1]
    today_day = datetime.date.today().day
    expected_key = "danh" + str(user_id * today_day - 20207) 

    if key == expected_key:
        text_message = f'<blockquote>[ KEY HỢP LỆ ] NGƯỜI DÙNG CÓ ID: [ {user_id} ] ĐƯỢC PHÉP ĐƯỢC SỬ DỤNG CÁC LỆNH TRONG [/help]</blockquote>'
       
        video_url = 'https://v16m-default.akamaized.net/4e91716006f611b4064fb417539f7a57/66a9164c/video/tos/alisg/tos-alisg-pve-0037c001/o4VRzDLftQGT9YgAc2pAefIqZeIoGLgGAFIWtF/?a=0&bti=OTg7QGo5QHM6OjZALTAzYCMvcCMxNDNg&ch=0&cr=0&dr=0&lr=all&cd=0%7C0%7C0%7C0&cv=1&br=2138&bt=1069&cs=0&ds=6&ft=XE5bCqT0majPD12fFa-73wUOx5EcMeF~O5&mime_type=video_mp4&qs=0&rc=PGloZWg2aTVoOGc7OzllZkBpanA0ZXA5cjplczMzODczNEAtXmAwMWEyXjUxNWFgLjYuYSNxZ3IyMmRrNHNgLS1kMS1zcw%3D%3D&vvpl=1&l=20240730103502EC9CCAF9227AE804B708&btag=e00088000'  # Đổi URL đến video của bạn
        bot.send_video(message.chat.id, video_url, caption=text_message, parse_mode='HTML')
        
        user_path = f'./user/{today_day}'
        os.makedirs(user_path, exist_ok=True)
        with open(f'{user_path}/{user_id}.txt', "w") as fi:
            fi.write("")
    else:
        bot.reply_to(message, 'KEY KHÔNG HỢP LỆ.')






# Lệnh /spam


user_last_command_time = {}
user_spam_count = {}

@bot.message_handler(commands=['spam'])
def supersms(message):
    user_id = message.from_user.id
    today_day = datetime.date.today().day
    today_path = f"./user/{today_day}/{user_id}.txt"

    if not os.path.exists(today_path):
        bot.reply_to(message, 'Dùng /getkey Để Lấy Key Hoặc /muavip Và Dùng /key Để Nhập Key Hôm Nay!')
        return

    current_time = time.time()

    if user_id in user_last_command_time:
        elapsed_time = current_time - user_last_command_time[user_id]
        if elapsed_time < 100:  
            remaining_time = 100 - elapsed_time
            bot.reply_to(message, f"Vui lòng đợi {remaining_time:.1f} giây trước khi sử dụng lệnh lại.")
            return

    params = message.text.split()[1:]
    if len(params) != 2:
        bot.reply_to(message, "/spam sdt số_lần max 10")
        return

    sdt, count = params

    if not count.isdigit():
        bot.reply_to(message, "Số lần spam không hợp lệ. Vui lòng chỉ nhập số.")
        return

    count = int(count)

    if count > 10:
        bot.reply_to(message, "/spam sdt số_lần tối đa là 10")
        return

    if sdt in blacklist:
        bot.reply_to(message, f"Số điện thoại {sdt} đã bị cấm spam.")
        return

    sdt_request = f"84{sdt[1:]}" if sdt.startswith("0") else sdt

    diggory_chat3 = f'''┌──────⭓ {name_bot}
│ Spam: Thành Công 
│ Người dùng: {message.from_user.username}
│ Số Lần Spam: {count}
│ Đang Tấn Công: {sdt}
└─────────────'''

    script_filename = "sms.py"

    try:
        if not os.path.isfile(script_filename):
            bot.reply_to(message, "Không tìm thấy file.")
            return

        with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as temp_file:
            with open(script_filename, 'r', encoding='utf-8') as file:
                temp_file.write(file.read().encode('utf-8'))
            temp_file_path = temp_file.name

        subprocess.Popen(["python", temp_file_path, sdt, str(count)])

        bot.send_message(
            message.chat.id,
            f'<blockquote>{diggory_chat3}</blockquote>\n<blockquote>GÓI NGƯỜI DÙNG: FREE</blockquote>',
            parse_mode='HTML'
        )

        requests.get(f'https://dichvukey.site/apivl/call1.php?sdt={sdt_request}')
        user_last_command_time[user_id] = time.time()

    except Exception as e:
        print(f'Lỗi')
        
        

from telebot.types import Message

last_usage = {}
blacklist = ["112", "113", "114", "115", "116", "117", "118", "119", "0", "1", "2", "3", "4", "078901631"]

@bot.message_handler(commands=['spamvip'])
def spam_vip_handler(message: Message):
    user_id = message.from_user.id
    username = message.from_user.username or "Không có tên"

    if user_id not in allowed_users:
        bot.reply_to(message, "️*Bạn chưa có quyền sử dụng lệnh này!*\n💰 Hãy mua VIP để sử dụng.\nNhắn /muavip riêng với bot [@botvlongvip_bot]", parse_mode="Markdown")
        return

    params = message.text.split()[1:]
    if len(params) != 2:
        bot.reply_to(message, "❌ *Sai cú pháp!*\n\n✅ Đúng: `/spamvip số_điện_thoại số_lần`", parse_mode="Markdown")
        return

    sdt, count_str = params
    
    if not count_str.isdigit() or int(count_str) <= 0:
        bot.reply_to(message, "⚠️ *Số lần spam không hợp lệ!*\n🔢 Vui lòng nhập một số dương.", parse_mode="Markdown")
        return
    
    count = min(int(count_str), 50)

    if sdt in blacklist:
        bot.reply_to(message, f"🚫 *Số điện thoại {sdt} đã bị cấm spam!* 🚫", parse_mode="Markdown")
        return

    sdt_request = f"84{sdt[1:]}" if sdt.startswith("0") else sdt
    current_time = time.time()

    if user_id in last_usage and (current_time - last_usage[user_id]) < 678:
        remaining_time = 678 - (current_time - last_usage[user_id])
        bot.reply_to(message, f"⏳ *Hãy chờ {remaining_time:.1f} giây trước khi dùng lại!*", parse_mode="Markdown")
        return

    last_usage[user_id] = current_time

    message_content = (
        f"🎯 *Spam Thành Công!* 🎯\n"
        f"📌 Người dùng: @{username}\n"
        f"📲 Số điện thoại: `{sdt}`\n"
        f"🔢 Số lần spam: `{count}`\n"
        "⚠️ Lưu ý: Spam 50 lần mất khoảng 15 phút để hoàn tất.\n"
        "💎 Gói VIP giúp bạn spam hiệu quả hơn!"
    )

    script_filename = "sms.py"
    if not os.path.isfile(script_filename):
        bot.reply_to(message, "❌ *Lỗi: Không tìm thấy script SMS!*", parse_mode="Markdown")
        return

    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as temp_file:
            with open(script_filename, 'r', encoding='utf-8') as file:
                temp_file.write(file.read().encode('utf-8'))
            temp_file_path = temp_file.name

        subprocess.Popen(["python", temp_file_path, sdt, str(count)])
        bot.send_message(message.chat.id, message_content, parse_mode="Markdown")
        requests.get(f"https://dichvukey.site/apivl/call1.php?sdt={sdt_request}")
    except Exception as e:
        bot.reply_to(message, "❌ *Đã xảy ra lỗi khi thực thi!*", parse_mode="Markdown")
        print(f"Lỗi: {e}")
    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
            

voicebuoidau = ["lồn", "đong", "long", "bú", "vlong", "buồi", "cặc"]

@bot.message_handler(commands=['voice'])
def text_to_voice(message):
    text = message.text[7:].strip()  
    if not text:
        bot.reply_to(message, 'Nhập nội dung đi VD: /voice vờ long zét zét')
        return

    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.mp3') as temp_file:
            tts = gTTS(text, lang='vi')
            tts.save(temp_file.name)
            temp_file_path = temp_file.name  
       
        with open(temp_file_path, 'rb') as f:
            bot.send_voice(message.chat.id, f, reply_to_message_id=message.message_id)
        if any(word in text.lower() for word in voicebuoidau):
            user_id = message.from_user.id
            bot.reply_to(message, f"ID {user_id} !")

    except Exception as e:
        bot.reply_to(message, f'Đã xảy ra lỗi')
    
    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
            
#voice
@bot.message_handler(commands=['id', 'ID'])
def handle_id_command(message):
    if message.reply_to_message:  
        user_id = message.reply_to_message.from_user.id
        first_name = message.reply_to_message.from_user.first_name
        bot.reply_to(message, f"ID của {first_name} là: `{user_id}`", parse_mode='Markdown')
    elif len(message.text.split()) == 1:
        if message.chat.type in ["group", "supergroup"]:
            chat_id = message.chat.id
            chat_title = message.chat.title
            bot.reply_to(message, f"ID của nhóm này là: `{chat_id}`\nTên nhóm: {chat_title}", parse_mode='Markdown')
        else:
            user_id = message.from_user.id
            first_name = message.from_user.first_name
            bot.reply_to(message, f"ID của bạn là: `{user_id}`\nTên: {first_name}", parse_mode='Markdown')
   

@bot.message_handler(commands=['tv'])
def tieng_viet(message):
    chat_id = message.chat.id
    message_id = message.message_id
    keyboard = types.InlineKeyboardMarkup()
    url_button = types.InlineKeyboardButton("Tiếng Việt 🇻🇳", url='https://t.me/setlanguage/abcxyz')
    keyboard.add(url_button)
    bot.send_message(chat_id, 'Click vào nút "<b>Tiếng Việt</b>" để đổi thành ngôn ngữ Việt Nam.', reply_markup=keyboard, parse_mode='HTML')
######
#####

@bot.message_handler(commands=['code'])
def handle_code_command(message):
    command_args = message.text.split(maxsplit=1)
    if len(command_args) < 2:
        bot.reply_to(message, "Ví dụ: /code https://vlongzZ.com")
        return

    url = command_args[1]
    domain = urlparse(url).netloc
    file_name = f"{domain}.txt"
    
    try:
        response = requests.get(url)
        response.raise_for_status()  

        with open(file_name, 'w', encoding='utf-8') as file:
            file.write(response.text)
        with open(file_name, 'rb') as file:
            bot.send_document(message.chat.id, file, caption=f"HTML của trang web {url}")
        bot.reply_to(message, "Đã gửi mã nguồn HTML của trang web cho bạn.")

    except requests.RequestException as e:
        bot.reply_to(message, f"Đã xảy ra lỗi khi tải trang web: {e}")

    finally:
        if os.path.exists(file_name):
            try:
                os.remove(file_name)
            except Exception as e:
                bot.reply_to(message, f"Đã xảy ra lỗi khi xóa file: {e}")














##gggg


GOOGLE_API_KEY = "AIzaSyCADJDxSt6q_bn_YuPi34O7rVgdWw6onMI"
CSE_ID = "058ec56e91b3748a3"

# Bộ lọc từ nhạy cảm
SENSITIVE_WORDS = [
    "buồi", "gay", "sexy", "che", "hd", "lồn", "xec", "haiten", "viet69", "ditnhau", "segay", "xnhau",
    "uuuu", "cu", "bú", "chim", "nhau", "dí", "dương vật", "hentai", "chịch",
    "sex", "địt", "cặc"
]

COOLDOWN_TIME = 10
last_command_timegg = {}
@bot.message_handler(commands=['gg'])
def search_and_reply(message):
    global last_command_timegg, allowed_users  

    user_id = message.from_user.id
    today_day = datetime.date.today().day
    key_path = f"./user/{today_day}/{user_id}.txt"
    if user_id not in allowed_users and not os.path.exists(key_path):
        reply_text = (
            "<blockquote>⚠️ Bạn chưa nhập key! ⚠️\n"
            "Dùng <b>/getkey</b> để lấy key và <b>/key</b> để nhập.</blockquote>"
        )
        bot.reply_to(message, reply_text, parse_mode="HTML")
        return

    current_time = time.time()
    if user_id in last_command_timegg and current_time - last_command_timegg[user_id] < COOLDOWN_TIME:
        time_left = int(COOLDOWN_TIME - (current_time - last_command_timegg[user_id]))
        bot.reply_to(message, f"⏳ Bạn phải đợi {time_left} giây trước khi dùng lại lệnh!")
        return
    query = message.text[4:].strip()
    if not query:
        bot.reply_to(message, "/gg siêu nhân", parse_mode="Markdown")
        return
    for word in SENSITIVE_WORDS:
        if f" {word} " in f" {query.lower()} ":
            bot.reply_to(message, "Não Của Bạn Đang Bị Lỗi!")
            return

    last_command_timegg[user_id] = current_time
    search_url = f"https://www.googleapis.com/customsearch/v1?key={GOOGLE_API_KEY}&cx={CSE_ID}&q={query}&searchType=image"
    response = requests.get(search_url)

    if response.status_code == 200:
        search_results = response.json()
        if "items" in search_results:
            random_item = random.choice(search_results["items"])
            image_url = random_item["link"]
            try:
                bot.send_photo(message.chat.id, photo=image_url, caption=f"🔍 Kết quả cho: *{query}*", parse_mode="Markdown")
            except Exception as e:
                bot.reply_to(message, "Lỗi khi gửi ảnh.")
                print(f"Lỗi: {e}")
        else:
            bot.reply_to(message, "Không tìm thấy hình ảnh nào.")
    else:
        bot.reply_to(message, "Lỗi khi tìm kiếm trên Google.")


#thoitiet

API_KEY = '1dcdf9b01ee855ab4b7760d43a10f854'
def anv(city):
    base_url = f'http://api.openweathermap.org/data/2.5/weather?q={city}&appid={API_KEY}&units=metric'
    tna = requests.get(base_url)
    nan = tna.json()

    if nan['cod'] == 200:
        weather_info = nan['weather'][0]['description']
        icon = nan['weather'][0]['main']
        temp_info = nan['main']['temp']
        feels_like = nan['main']['feels_like']
        temp_min = nan['main']['temp_min']
        temp_max = nan['main']['temp_max']
        city = nan['name']
        lat = nan['coord']['lat']
        lon = nan['coord']['lon']
        country = nan['sys']['country']
        all = nan['clouds']['all']
        humidity_info = nan['main']['humidity']
        wind_speed_info = nan['wind']['speed']
        gg = f"(https://www.google.com/maps/place/{lat},{lon})"
        return f'╭─────⭓Thời Tiết\n│🌍 City: {city}\n│🔗 Link map: [{city}]{gg}\n│☁️ Thời tiết: {weather_info}\n│🌡 Nhiệt độ: {temp_info}°C\n│🌡️ Nhiệt độ cảm nhận: {feels_like}°C\n│🌡️ Nhiệt độ tối đa: {temp_max}°C\n│🌡️ Nhiệt độ tối thiểu: {temp_min}°C\n│📡 Tình trạng thời tiết: {icon}\n│🫧 Độ ẩm: {humidity_info}%\n│☁️ Mức độ mây: {all}%\n│🌬️ Tốc độ gió: {wind_speed_info} m/s\n│🌐 Quốc gia: {country}.\n╰─────────────⭓'
    else:
        return 'Không tìm thấy thông tin thời tiết cho địa điểm này.'

@bot.message_handler(commands=['thoitiet'])
def thoitiet(message):
    parts = message.text.split()
    if len(parts) == 1:
        bot.reply_to(message, 'Nhập đúng định dạng:\n/thoitiet [Tên tỉnh thành]')
        return
    city = ' '.join(parts[1:])
    annn = anv(city)
    bot.reply_to(message, annn, parse_mode='Markdown')


#hoi
@bot.message_handler(commands=['hoi'])
def handle_hoi(message):
    text = message.text[len('/hoi '):].strip()
    
    if text:
        url = f"https://dichvukey.site/apishare/hoi.php?text={text}"
        response = requests.get(url)
        
        if response.status_code == 200:
            data = response.json()
            reply = data.get("message", "Không có phản hồi.")
        else:
            reply = "Lỗi."
    else:
        reply = "Lệnh Ví Dụ : /hoi xin chào."
    bot.reply_to(message, reply)
#tai 
@bot.message_handler(commands=['tai'])
def handle_tai(message):
    if len(message.text.split(' ', 1)) < 2:
        bot.reply_to(message, "Lệnh không đúng. Vui lòng sử dụng: /tai [link]")
        return

    link = message.text.split(' ', 1)[1]

    try:
        response = requests.get(link)
        response.raise_for_status()
        filename = os.path.basename(link)
        with open(filename, 'w', encoding='utf-8') as file:
            file.write(response.text)
        with open(filename, 'rb') as file:
            bot.send_document(
                message.chat.id,
                file,
                caption=f"@{message.from_user.username} File Của Bạn Đây Nhé."
            )

    except requests.exceptions.RequestException as e:
        bot.reply_to(message, f"Lỗi Rồi")
    except Exception as e:
        bot.reply_to(message, f"Lỗi Rồi")
#tik





#viewtiktok



@bot.message_handler(commands=['viewtiktok'])
def view_tiktok(message):
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        bot.reply_to(message, '/viewtiktok Link', parse_mode='HTML')
        return
    
    video_url = parts[1].strip()
    api_url = f'https://www.tikwm.com/api?url={video_url}'

    try:
        response = requests.get(api_url)
        response.raise_for_status()
        data = response.json()

        if 'error' in data:
            bot.reply_to(message, f'<blockquote>Đã xảy ra lỗi: {data["error"]}</blockquote>', parse_mode='HTML')
        else:
            play_count = data.get('data', {}).get('play_count', 'Không có thông tin')
            bot.reply_to(message, f'<blockquote>\n'
                                  f'{play_count} View.</blockquote>', parse_mode='HTML')
    except requests.RequestException as e:
        bot.reply_to(message, f'<blockquote>Lỗi Ròi HuHuHu</blockquote>', parse_mode='HTML')


#thongtin
@bot.message_handler(commands=['tele'])

def handle_checktele(message):
    user_id = message.from_user.id
    user_name = message.from_user.first_name
    user_username = message.from_user.username
    user_link = f"<a href='tg://user?id={user_id}'>{user_name}</a>"

    try:
        photos = bot.get_user_profile_photos(user_id)
        if photos.total_count > 0:
            avatar_file_id = photos.photos[0][0].file_id
            info_text = (
                f"<blockquote>Thông Tin Người Dùng:\n"
                f"Tên: {user_name}\n"
                f"User ID: {user_id}\n"
                f"UserName: @{user_username if user_username else 'Không có'}\n"
                f"Link Người Dùng: {user_link}</blockquote>"
            )
            bot.send_photo(message.chat.id, avatar_file_id, caption=info_text, parse_mode="HTML")
        else:
            info_text = (
                f"<blockquote>Thông Tin Người Dùng:\n"
                f"Tên: {user_name}\n"
                f"User ID: {user_id}\n"
                f"UserName: @{user_username if user_username else 'Không có'}\n"
                f"Link Người Dùng: {user_link}</blockquote>"
            )
            bot.send_message(message.chat.id, info_text, parse_mode="HTML")
    except Exception as e:
        bot.send_message(message.chat.id, f"Đã xảy ra lỗi: {str(e)}")
        
#dinhgiasim




def infoo(username):
    url = f'https://dichvukey.site/apivl/tiktokne.php?user={username}'
    try:
        response = requests.get(url)
        data = response.json()
        if data['code'] != 10200:
            return "Không tìm thấy thông tin người dùng."

        user_info = data['info']['userInfo']['user']
        stats = data['info']['userInfo']['stats']
        message = f"<blockquote>🔍 *Thông tin người dùng TikTok*:\n\n"
        message += f"Tên tài khoản: {user_info['uniqueId']}\n"
        message += f"Biệt danh: {user_info['nickname']}\n"
        message += f"Thời gian tạo: {user_info['createTime']}\n"
        message += f"Khu vực: {user_info['region']}\n"
        message += f"Ảnh đại diện (lớn): <a href='{user_info['avatarLarger']}'>Nhấp để xem</a>\n"
        message += f"Ảnh đại diện (vừa): <a href='{user_info['avatarMedium']}'>Nhấp để xem</a>\n"
        message += f"Ảnh đại diện (nhỏ): <a href='{user_info['avatarThumb']}'>Nhấp để xem</a>\n\n"
        message += f"Thống kê:\n"
        message += f"Số người theo dõi: {stats['followerCount']}\n"
        message += f"Số người đang theo dõi: {stats['followingCount']}\n"
        message += f"Tổng lượt thích: {stats['heartCount']}\n"
        message += f"Số video: {stats['videoCount']}</blockquote>\n"

        return message
    except requests.RequestException as e:
        return f"Lỗi"
    except KeyError as e:
        return f"Lỗi"
    except Exception as e:
        return f"Lỗi"

@bot.message_handler(commands=['tik'])
def send_tiktok_info(message):
    try:
        parts = message.text.split()
        if len(parts) > 1:
            username = parts[1]
            response_message = infoo(username)
        else:
            response_message = "Lệnh ví dụ: /tik vlongzzne"
        
        bot.reply_to(message, response_message, parse_mode='HTML')
    except Exception as e:
        bot.reply_to(message, f"Lỗi")





###like



import os
import datetime
import requests
from telebot import TeleBot
from telebot.types import Message



@bot.message_handler(commands=['like'])
def like_handler(message: Message):
    user_id = message.from_user.id
    today_day = datetime.date.today().day
    key_path = f"./user/{today_day}/{user_id}.txt"

    if user_id not in allowed_users and not os.path.exists(key_path):
        bot.reply_to(
            message,
            "<blockquote>⚠️ Bạn chưa nhập key! ⚠️\nDùng /getkey hoặc /muavip để sử dụng.</blockquote>",
            parse_mode="HTML"
        )
        return

    command_parts = message.text.split()
    if len(command_parts) != 2:
        bot.reply_to(message, "<blockquote>/like 1733997441</blockquote>", parse_mode="HTML")
        return

    idgame = command_parts[1]
    url = f"https://likes-freefire.vercel.app/likes?uid={idgame}&region=vn&key=GoodKey"

    def safe_get(data, key):
        value = data.get(key)
        return value if value not in [None, "", 0] else "Không xác định"

    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException:
        bot.reply_to(message, "<blockquote>⚠️ Server đang quá tải, vui lòng thử lại sau.</blockquote>", parse_mode="HTML")
        return
    except ValueError:
        bot.reply_to(message, "<blockquote>⚠️ Phản hồi từ server không hợp lệ.</blockquote>", parse_mode="HTML")
        return

    if data.get("status") != 1:
        bot.reply_to(message, "<blockquote>⚠️ Thao tác không thành công, vui lòng thử lại sau.</blockquote>", parse_mode="HTML")
        return

    reply_text = (
        f"<blockquote>\n"
        f"👤 <b>Tên:</b> {safe_get(data, 'PlayerNickname')}\n"
        f"🆔 <b>UID:</b> {safe_get(data, 'UID')}\n"
        f"👍 <b>Like trước:</b> {safe_get(data, 'LikesbeforeCommand')}\n"
        f"✅ <b>Like sau:</b> {safe_get(data, 'LikesafterCommand')}\n"
        f"➕ <b>Số like buff:</b> {safe_get(data, 'LikesGivenByAPI')}\n"
        f"────────────────────\n"
        f"🔗 <b>Mua Follow MXH uy tín:</b> https://dvmangxahoiuytin.site/home\n"
        f"</blockquote>"
    )

    bot.reply_to(message, reply_text, parse_mode="HTML")
    #
    #like
    

###

import requests
import urllib3
import time
from telebot import TeleBot

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  

@bot.message_handler(commands=['visit'])
def visit_handler(message):
    args = message.text.split()
    if len(args) != 2:
        bot.reply_to(message, "`/visit 1733997441`", parse_mode="Markdown")
        return

    idgame = args[1]
    url = f'https://tanhungfreefirevisit.vercel.app/visitorsff?uid={idgame}&region=vn'

    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = requests.get(url, timeout=10, verify=False)
            response.raise_for_status()

            data = response.json()

            if not data.get("success", False):
                bot.reply_to(message, "Lỗi rồi, báo admin fix đi.", parse_mode="Markdown")
                return

            reply_text = (
                f"✅ *Thành công*\n"
                f"👀 *Tổng lượt xem:* `{data['message']}`\n"
                f"*Sever UID:* `{data['region']}`"
            )
            bot.reply_to(message, reply_text, parse_mode="Markdown")
            return

        except:
            if attempt < max_retries - 1:
                time.sleep(1)
                continue
            else:
                bot.reply_to(message, "*Server đang quá tải hoặc lỗi, vui lòng thử lại sau.*", parse_mode="Markdown")




from html import escape
@bot.message_handler(commands=['ngl'])
def ngl(message):
    user_id = message.from_user.id
    today_day = datetime.date.today().day
    key_path = f"./user/{today_day}/{user_id}.txt"

    if user_id not in allowed_users and not os.path.exists(key_path):
        bot.reply_to(
            message,
            "⚠️ *Bạn chưa nhập key!* ⚠️\nDùng /muavip hoặc /getkey để lấy key.",
            parse_mode="Markdown"
        )
        return

    args = message.text.split()
    if len(args) != 3:
        bot.reply_to(message, "`/ngl username 10 [max20]`", parse_mode="Markdown")
        return

    username = args[1]
    try:
        count = min(20, int(args[2]))
    except ValueError:
        bot.reply_to(message, "số thôi.", parse_mode="Markdown")
        return

    url = "https://ngl.link/api/submit"

    headers = {
        'Host': 'ngl.link',
        'accept': '*/*',
        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'x-requested-with': 'XMLHttpRequest',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36',
        'origin': 'https://ngl.link',
        'referer': f'https://ngl.link/{username}',
    }

    data = {
        'username': username,
        'question': 'Tin nhắn spam từ bot  @Congdanh1_bot',
        'deviceId': '0',
        'gameSlug': '',
        'referrer': '',
    }

    success_count = 0
    for _ in range(count):
        try:
            response = requests.post(url, headers=headers, data=data, timeout=10)
            response.raise_for_status()
            success_count += 1
        except requests.exceptions.RequestException:
            pass

    reply_text = (
        f"✅ *Thành công*\n"
        f"👤 *Người gửi:* @{message.from_user.username}\n"
        f"📨 *Đã gửi:* `{success_count}/{count}` tin nhắn\n"
        f"🎯 *Người nhận:* @{username}"
        f"<b>Mua Follow MXH uy tín : https://dvmangxahoiuytin.site/home\n"
    )

    bot.reply_to(message, reply_text, parse_mode="Markdown")


#like1
#name






@bot.message_handler(commands=['name'])
def name_handler(message: Message):
    user_id = message.from_user.id
    today_day = datetime.date.today().day
    key_path = f"./user/{today_day}/{user_id}.txt"

    if user_id not in allowed_users and not os.path.exists(key_path):  
        bot.reply_to(
            message,
            "<blockquote>⚠️ Bạn chưa nhập key! ⚠️\nDùng /getkey hoặc /muavip để sử dụng.</blockquote>",
            parse_mode="HTML"
        )
        return

    command_parts = message.text.split(maxsplit=1)
    if len(command_parts) != 2:
        bot.reply_to(message, "<blockquote>/name name</blockquote>", parse_mode="HTML")
        return

    keyword = command_parts[1]
    url = f"https://ariflexlabs-search-api.vercel.app/search?name={keyword}"

    def format_time(timestamp):
        try:
            return datetime.datetime.fromtimestamp(int(timestamp)).strftime("%d/%m/%Y %H:%M")
        except:
            return "Không xác định"

    try:
        res = requests.get(url, timeout=15)
        res.raise_for_status()
        data = res.json()
    except requests.exceptions.RequestException:
        bot.reply_to(message, "<blockquote>Server đang quá tải, vui lòng thử lại sau.</blockquote>", parse_mode="HTML")
        return
    except ValueError:
        bot.reply_to(message, "<blockquote>Phản hồi từ server không hợp lệ.</blockquote>", parse_mode="HTML")
        return

    vn_players = []
    other_players = []

    for region_entry in data:
        region = region_entry.get("region", "").upper()
        players = region_entry.get("result", {}).get("player", [])
        for p in players:
            entry = {
                "uid": p.get("accountId"),
                "name": p.get("nickname"),
                "level": p.get("level", "N/A"),
                "region": p.get("region", region),
                "lastLogin": format_time(p.get("lastLogin"))
            }
            if entry["region"] == "VN":
                vn_players.append(entry)
            else:
                other_players.append(entry)

    final_list = vn_players[:5] if len(vn_players) >= 1 else other_players[:5]

    if not final_list:
        bot.reply_to(message, "<blockquote>Không tìm thấy tài khoản nào phù hợp.</blockquote>", parse_mode="HTML")
        return

    reply_text = "<b>Kết quả tìm kiếm:</b>\n"
    for idx, player in enumerate(final_list, start=1):
        reply_text += (
            f"\n<b>{idx}. {player['name']}</b>\n"
            f"🆔 UID: <code>{player['uid']}</code>\n"
            f"🎚 Level: {player['level']}\n"
            f"🌍 Khu vực: {player['region']}\n"
            f"⏰ Online: {player['lastLogin']}\n"
        )

    bot.reply_to(message, reply_text, parse_mode="HTML")
  
#



@bot.message_handler(commands=['ff'])
def ff_handler(message: Message):
    user_id = message.from_user.id
    today_day = datetime.date.today().day
    key_path = f"./user/{today_day}/{user_id}.txt"

    if user_id not in allowed_users and not os.path.exists(key_path):  
        bot.reply_to(
            message,
            "<blockquote>⚠️ Bạn chưa nhập key! ⚠️\nDùng /getkey hoặc /muavip để sử dụng.</blockquote>",
            parse_mode="HTML"
        )
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        bot.reply_to(message, "<blockquote>/ff 1733997441</blockquote>", parse_mode="HTML")
        return

    idgame = command_parts[1]
    url = f"https://ariiflexlabs-playerinfo-icxc.onrender.com/ff_info?uid={idgame}&region=vn"

    def safe_get(data, key):
        value = data.get(key)
        return value if value not in [None, ""] else "Không xác định"

    def format_time(timestamp):
        try:
            return datetime.datetime.fromtimestamp(int(timestamp)).strftime("%d/%m/%Y %H:%M")
        except:
            return "Không xác định"

    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException:
        bot.reply_to(message, "<blockquote>Server đang quá tải, vui lòng thử lại sau.</blockquote>", parse_mode="HTML")
        return
    except ValueError:
        bot.reply_to(message, "<blockquote>Phản hồi từ server không hợp lệ.</blockquote>", parse_mode="HTML")
        return

    info = data.get("AccountInfo", {})
    social = data.get("socialinfo", {})
    pet = data.get("petInfo", {})

    reply_text = (
        f"<b>👤 Tên:</b> {safe_get(info, 'AccountName')}\n"
        f"<b>🆔 UID:</b> {idgame}\n"
        f"<b>🌍 Khu vực:</b> {safe_get(info, 'AccountRegion')}\n"
        f"<b>🎚 Level:</b> {safe_get(info, 'AccountLevel')}\n"
        f"<b>👍 Lượt like:</b> {safe_get(info, 'AccountLikes')}\n"
        f"<b>⏰ Tạo lúc:</b> {format_time(info.get('AccountCreateTime'))}\n"
        f"<b>🔓 Đăng nhập cuối:</b> {format_time(info.get('AccountLastLogin'))}\n"
        f"<b>💬 Chữ ký:</b> {safe_get(social, 'AccountSignature')}\n"
        f"<b>Mua Follow MXH uy tín : https://dvmangxahoiuytin.site/home\n"
    )

    if pet:
        reply_text += (
            f"\n<b>🐾 Pet:</b> {safe_get(pet, 'name')} (Level {safe_get(pet, 'level')})\n"
        )

    reply_text += "\n<blockquote>@vanlongvippro</blockquote>"

    bot.reply_to(message, reply_text, parse_mode="HTML")

####bò

@bot.message_handler(commands=['video'])
def send_random_video(message):
    user_id = message.from_user.id
    full_name = message.from_user.full_name
    mention = f"[{full_name}](tg://user?id={user_id})"
    today = datetime.date.today().day
    key_path = f"./user/{today}/{user_id}.txt"

    if user_id not in allowed_users and not os.path.exists(key_path):
        bot.reply_to(
            message,
            f"⚠️ {mention}, bạn chưa nhập key!\nDùng /muavip hoặc /getkey để lấy key.",
            parse_mode="Markdown"
        )
        return

    try:
        response = requests.get("https://api.ffcommunity.site/randomvideo.php", timeout=10)
        if response.status_code == 200:
            data = response.json()
            video_url = data.get("url")
            if video_url:
                caption = f"🎬 Video ngẫu nhiên cho {mention} đây nè!"
                bot.send_video(message.chat.id, video_url, caption=caption, parse_mode="Markdown")
            else:
                bot.reply_to(message, "Không lấy được video.")
        else:
            bot.reply_to(message, "API lỗi hoặc không phản hồi.")
    except Exception as e:
        bot.reply_to(message, f"Đã xảy ra lỗi", parse_mode="Markdown")


##



@bot.message_handler(commands=['fl'])
def fl_handler(message):
    user_id = message.from_user.id
    today_day = datetime.date.today().day
    key_path = f"./user/{today_day}/{user_id}.txt"

    if user_id not in allowed_users and not os.path.exists(key_path):
        bot.reply_to(
            message,
            "<blockquote>⚠️ Bạn chưa nhập key! ⚠️\nDùng /getkey hoặc /muavip để sử dụng.</blockquote>",
            parse_mode="HTML"
        )
        return

    command_parts = message.text.split()
    if len(command_parts) != 2:
        bot.reply_to(message, "<blockquote>/fl username</blockquote>", parse_mode="HTML")
        return

    username = command_parts[1]
    if username.startswith("@"):
        username = username[1:]

    url = f"https://dichvukey.site/fl.php?username={username}"

    try:
        response = requests.get(url)
        data = response.json()
    except Exception as e:
        bot.reply_to(message, f"<blockquote>Lỗi khi gọi API: {e}</blockquote>", parse_mode="HTML")
        return

    if not data.get("success"):
        bot.reply_to(message, f"<blockquote>Lỗi: {data.get('message', 'Không rõ lỗi')}</blockquote>", parse_mode="HTML")
        return

    reply_text = (
        f"<b>📢 Buff follower thành công!</b>\n"
        f"<b>🧑 Nickname:</b> {safe_get(data, 'nickname')}\n"
        f"<b>🔰 Username:</b> @{safe_get(data, 'username')}\n"
        f"<b>🆔 User ID:</b> <code>{safe_get(data, 'user_id')}</code>\n"
        f"<b>📉 Trước:</b> {safe_get(data, 'before')} followers\n"
        f"<b>📈 Sau:</b> {safe_get(data, 'after')} followers\n"
        f"<b>➕ Tăng thêm:</b> <b>{safe_get(data, 'increase')}</b> người\n"
        f"<b>📜 Message:</b> {safe_get(data, 'message')}\n"
        f"<b>Mua Follow MXH uy tín : https://dvmangxahoiuytin.site/home\n"
        "\n<blockquote>api by : @Anvipvcl</blockquote>"
    )

    bot.reply_to(message, reply_text, parse_mode="HTML")
    
 ####


if __name__ == "__main__":
    bot_active = True
    bot.infinity_polling()

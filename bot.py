def extract_uid_from_command(cleaned_message, command, default_id="2060437760"):
    import re
    player_id = default_id
    try:
        id_match = re.search(rf'/{command}/(\d{{5,15}})\b', cleaned_message)
        if id_match:
            player_id = id_match.group(1)
            if not (5 <= len(player_id) <= 15) or not player_id.isdigit():
                player_id = default_id
        else:
            temp_id = cleaned_message.split(f'/{command}/')[1].split()[0].strip()
            temp_id = temp_id.replace("***", "106") if "***" in temp_id else temp_id
            player_id = temp_id if temp_id.isdigit() and len(temp_id) >= 5 else default_id
    except Exception as e:
        print(f"UID extraction error for /{command}/: {e}")
        player_id = default_id
    return player_id
    
import threading
import httpx
import jwt
import random
from threading import Thread
import json
from AmdtsModzRemoveFriend import Xoakb
from amdtsmodz import AddFr
import threading
import time
bot_start_time = time.time()

import requests 
import google.protobuf
from protobuf_decoder.protobuf_decoder import Parser
import json
from datetime import datetime, timedelta
ADMIN_UID = ["12932432883", "440545497"]  

AmdtsModzRemoveFriend = Xoakb()
amdtsmodz = AddFr()
def encrypt_packet(plain_text, key, iv):
    plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def add_days(uid, days):
    try:
        with open("allowed_users.json", "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        data = {}

    now = datetime.now()
    if uid in data:
        expire_datetime = datetime.strptime(data[uid], "%Y-%m-%d")
        if expire_datetime < now:
            expire_datetime = now
    else:
        expire_datetime = now


    expire_datetime += timedelta(days=days)
    data[uid] = expire_datetime.strftime("%Y-%m-%d")  

    with open("allowed_users.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

    return expire_datetime

import psutil
import shutil

def get_system_info():

    cpu_percent = psutil.cpu_percent(interval=1)

    total, used, free = shutil.disk_usage("/")
    total_gb = total / (1024 ** 3)
    used_gb = used / (1024 ** 3)
    free_gb = free / (1024 ** 3)

    ram = psutil.virtual_memory()
    ram_total = ram.total / (1024 ** 3)
    ram_used = ram.used / (1024 ** 3)
    ram_percent = ram.percent

    return cpu_percent, total_gb, used_gb, free_gb, ram_total, ram_used, ram_percent

def get_uptime():
    uptime_seconds = time.time() - bot_start_time
    days = int(uptime_seconds // 86400)
    hours = int((uptime_seconds % 86400) // 3600)
    minutes = int((uptime_seconds % 3600) // 60)
    seconds = int(uptime_seconds % 60)
    return days, hours, minutes, seconds

import json
from datetime import datetime

def count_active_vip_users():
    try:
        with open("allowed_users.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        now = datetime.now().date()
        active_users = 0

        for uid, expire_date in data.items():
            try:
                expire = datetime.strptime(expire_date, "%Y-%m-%d").date()
                if expire >= now:
                    active_users += 1
            except:
                continue

        return active_users

    except FileNotFoundError:
        return 0

from datetime import datetime
import json

def get_vip_info(uid):
    try:
        with open("allowed_users.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        uid = str(uid)
        if uid not in data:
            return {"role": "FREE", "days": 0, "hours": 0, "minutes": 0, "seconds": 0}

        expire_date = datetime.strptime(data[uid], "%Y-%m-%d")
        now = datetime.now()
        remaining = expire_date - now

        if remaining.total_seconds() <= 0:
            return {"role": "FREE", "days": 0, "hours": 0, "minutes": 0, "seconds": 0}

        total_days = remaining.days
        role = f"VIP {max(1, (total_days // 7) + 1)}"

        return {
            "role": role,
            "days": total_days,
            "hours": remaining.seconds // 3600,
            "minutes": (remaining.seconds % 3600) // 60,
            "seconds": remaining.seconds % 60
        }

    except Exception as e:
        print(f"Lỗi khi lấy VIP info: {e}")
        return {"role": "FREE", "days": 0, "hours": 0, "minutes": 0, "seconds": 0}

def is_user_allowed(uid):
    try:
        with open("allowed_users.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        
        uid = str(uid)
        if uid not in data:
            return False, "[C][B][C0C0C0]Xin Lỗi Tài Khoản Của Bạn Hiện Tại Chưa Được Phép Sử D[c]ụ[c]n[c]g Bot Vui Lòng L[c]i[c]ê[c]n H[c]ệ Cho Admin Để Đ[c]ư[c]ợ[c]c H[c]ỗ T[c]r[c]ợ\n[ffffff]T[c]e[c]le[c]gr[c]a[c]m: [b][c][11EAFD]@cdanhdev"

        expire_date = datetime.strptime(data[uid], "%Y-%m-%d").date()
        today = datetime.now().date()

        if today > expire_date:
            return False, f"[C][B][C0C0C0]Xin Chào Q[c]u[c]ý K[c]h[c]á[c]c[c]h C[c]ũ Tài Khoản Này Của Q[c]u[c]ý K[c]h[c]á[c]c[c]h Đã Hết Hạn Sử D[c]ụ[c]n[c]g Bot Vui Lòng L[c]i[c]ê[c]n H[c]ệ Cho Admin Để Gia Hạn Thêm\n[ffffff]T[c]e[c]le[c]gr[c]a[c]m: [b][c][11EAFD]@cdanhdev"

        return True, None
    except FileNotFoundError:
        return False, "File VIP chưa được tạo"
    except Exception as e:
        print(f"Lỗi khi check quyền: {e}")
        return False, "Lỗi hệ thống"




client_secret = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"

import json
import datetime
from datetime import datetime


chat_ip = "103.108.103.30"
chat_port = 39698

from google.protobuf.json_format import MessageToJson

import message_pb2
import data_pb2

import base64

import logging


freefire_version = "OB50"

import re
import socket
from google.protobuf.timestamp_pb2 import Timestamp

import jwt_generator_pb2
import os
import binascii

import sys
import psutil
import MajorLoginRes_pb2
from time import sleep

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time

import urllib3
from important_zitado import*
from byte import*
tempid = None

sent_inv = False
start_par = False
pleaseaccept = False

nameinv = "none"
idinv = 0
senthi = False
statusinfo = False

tempdata1 = None
tempdata = None
leaveee = False

leaveee1 = False
data22 = None
isroom = False

isroom2 = False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
def encrypt_packet(plain_text, key, iv):
    plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()
    
def gethashteam(hexxx):
    a = zitado_get_proto(hexxx)
    if not a:
        raise ValueError("Invalid hex format or empty response from zitado_get_proto")
    data = json.loads(a)
    return data['5']['7']
def getownteam(hexxx):
    a = zitado_get_proto(hexxx)
    if not a:
        raise ValueError("Invalid hex format or empty response from zitado_get_proto")
    data = json.loads(a)
    return data['5']['1']

def get_player_status(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)

    if "5" not in parsed_data or "data" not in parsed_data["5"]:
        return "OFFLINE"

    json_data = parsed_data["5"]["data"]

    if "1" not in json_data or "data" not in json_data["1"]:
        return "OFFLINE"

    data = json_data["1"]["data"]

    if "3" not in data:
        return "OFFLINE"

    status_data = data["3"]

    if "data" not in status_data:
        return "OFFLINE"

    status = status_data["data"]

    if status == 1:
        return "SOLO"
    
    if status == 2:
        if "9" in data and "data" in data["9"]:
            group_count = data["9"]["data"]
            countmax1 = data["10"]["data"]
            countmax = countmax1 + 1
            return f"INSQUAD ({group_count}/{countmax})"

        return "INSQUAD"
    
    if status in [3, 5]:
        return "INGAME"
    if status == 4:
        return "IN ROOM"
    
    if status in [6, 7]:
        return "IN SOCIAL ISLAND MODE .."

    return "NOTFOUND"
def get_idroom_by_idplayer(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)
    json_data = parsed_data["5"]["data"]
    data = json_data["1"]["data"]
    idroom = data['15']["data"]
    return idroom
def get_leader(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)
    json_data = parsed_data["5"]["data"]
    data = json_data["1"]["data"]
    leader = data['8']["data"]
    return leader
def generate_random_color():
	color_list = [
    "[00FF00][b][c]",
    "[FFDD00][b][c]",
    "[3813F3][b][c]",
    "[FF0000][b][c]",
    "[0000FF][b][c]",
    "[FFA500][b][c]",
    "[DF07F8][b][c]",
    "[11EAFD][b][c]",
    "[DCE775][b][c]",
    "[A8E6CF][b][c]",
    "[7CB342][b][c]",
    "[FF0000][b][c]",
    "[FFB300][b][c]",
    "[90EE90][b][c]"
    "[95EEDd][b][c]"
]
	random_color = random.choice(color_list)
	return  random_color

def fix_num(num):
    fixed = ""
    count = 0
    num_str = str(num)  

    for char in num_str:
        if char.isdigit():
            count += 1
        fixed += char
        if count == 3:
            fixed += "[c]"
            count = 0  
    return fixed


def fix_word(num):
    fixed = ""
    count = 0
    
    for char in num:
        if char:
            count += 1
        fixed += char
        if count == 3:
            fixed += "[c]"
            count = 0  
    return fixed
 
import requests


       
             
def check_banned_status(player_id):
   
    url = f"http://amin-team-api.vercel.app/check_banned?player_id={player_id}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return data  
        else:
            return {"error": f"Failed to fetch data. Status code: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}
      



def get_jwt_token():
    global jwt_token
    url = "https://ch9ayfa-jwt.vercel.app/get?uid=292828&password=833888"
    
    try:
        response = httpx.get(url)
        if response.status_code == 200:
            data = response.json()


            if "token" in data:
                jwt_token = data["token"]
                print(f"[+] JWT Token: {jwt_token}")


                with open("token.txt", "w") as f:
                    f.write(jwt_token)
            else:
                print("[!] Không tìm thấy trường 'token' trong phản hồi.")
        else:
            print(f"[!] Lỗi HTTP {response.status_code}: {response.text}")
    except httpx.RequestError as e:
        print(f"[!] Lỗi kết nối: {e}")
    except httpx.RequestError as e:
        print(f"Request error: {e}")
def token_updater():
    while True:
        get_jwt_token()
        time.sleep(8 * 3600)
token_thread = Thread(target=token_updater, daemon=True)
token_thread.start()

import requests

def send_likes(uid):
    try:
        likes_api_response = requests.get(
            f"https://free-like-api-aditya-ffm.vercel.app/like?uid={uid}&server_name=sg&key=@adityaapis"
        )
        
        message = ("""
[C][B][FF0000]━━━━━━━━━━━━
[FFFFFF]ID không hợp lệ hoặc đã bị lỗi. Vui lòng kiểm tra lại.
[FF0000]━━━━━━━━━━━━
""")
        
        if likes_api_response.status_code == 200:
            api_json_response = likes_api_response.json()
            
            status = api_json_response.get('status')
            
            if status != 2:  # chưa đạt max like
                player_name = api_json_response.get('PlayerNickname', 'Unknown')
                likes_before = api_json_response.get('LikesbeforeCommand', 0)
                likes_after = api_json_response.get('LikesafterCommand', 0)
                likes_added = api_json_response.get('LikesGivenByAPI', 0)
                
                message = f"""
[C][B][11EAFD]━━━━━━━━━━━━
[00FF00]Đã gửi lượt thích thành công!

[FFFFFF]Tên Người Chơi: [00FF00]{player_name}  
[FFFFFF]Likes Trước: [00FF00]{likes_before}  
[FFFFFF]Likes Sau: [00FF00]{likes_after}
[FFFFFF]Likes Đã Thêm: [00FF00]{likes_added}    
[C][B][11EAFD]━━━━━━━━━━━━
                """
            else:
                message = (
                    f"[C][B][FF0000]________\n"
                    f"Bạn đã đạt đến giới hạn lượt thích hàng ngày. Hãy thử lại sau 24 giờ."
                    f"________"
                )
                
        return message
    except Exception as e:
        return f"Error: {str(e)}"
        
def rrrrrrrrrrrrrr(number):
    if isinstance(number, str) and '***' in number:
        return number.replace('***', '106')
    return number

		
def Encrypt(number):
    number = int(number)
    encoded_bytes = []

    while True:
        byte = number & 0x7F  # استخراج أقل 7 بتات من الرقم
        number >>= 7  # تحريك الرقم لليمين بمقدار 7 بتات
        if number:
            byte |= 0x80  # تعيين البت الثامن إلى 1 إذا كان الرقم لا يزال يحتوي على بتات إضافية

        encoded_bytes.append(byte)
        if not number:
            break  # التوقف إذا لم يتبقى بتات إضافية في الرقم

    return bytes(encoded_bytes).hex()
    


def get_random_avatar():
	avatar_list = [
        '902027018', '902027019', '902027020', '902027021', '902027022', 
        '902027023', '902027024', '902027025', '902027026', '902027027', 
        '902027016', '902027017', '902040027', '902040028', '902042011','902048004', '902047018'
    ]
	random_avatar = random.choice(avatar_list)
	return  random_avatar

class FF_CLIENT(threading.Thread):
    def __init__(self, id, password):
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        self.get_tok()
    def connect(self, tok, host, port, packet, key, iv):
        global clients
        clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = int(port)
        clients.connect((host, port))
        clients.send(bytes.fromhex(tok))

        while True:
            data = clients.recv(9999)
            if data == b"":
                print("Connection closed by remote host")
                break
def get_available_room(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_objects = parsed_results
        parsed_results_dict = parse_results(parsed_results_objects)
        json_data = json.dumps(parsed_results_dict)
        return json_data
    except Exception as e:
        print(f"error {e}")
        return None

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data["wire_type"] = result.wire_type
        if result.wire_type == "varint":
            field_data["data"] = result.data
        if result.wire_type == "string":
            field_data["data"] = result.data
        if result.wire_type == "bytes":
            field_data["data"] = result.data
        elif result.wire_type == "length_delimited":
            field_data["data"] = parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict

def dec_to_hex(ask):
    ask_result = hex(ask)
    final_result = str(ask_result)[2:]
    if len(final_result) == 1:
        final_result = "0" + final_result
    return final_result

def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return binascii.hexlify(encrypted_message).decode('utf-8')

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def extract_jwt_from_hex(hex):
    byte_data = binascii.unhexlify(hex)
    message = jwt_generator_pb2.Garena_420()
    message.ParseFromString(byte_data)
    json_output = MessageToJson(message)
    token_data = json.loads(json_output)
    return token_data
    

def format_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

def restart_program():
    p = psutil.Process(os.getpid())
    open_files = p.open_files()
    for handler in open_files:
        try:
            os.close(handler.fd)
        except Exception:
            pass


    sys.path.append(os.path.dirname(os.path.abspath(sys.argv[0])))
    python = sys.executable
    os.execl(python, python, *sys.argv)
          
class FF_CLIENT(threading.Thread):
    def __init__(self, id, password):
        super().__init__()
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        self.get_tok()

    def parse_my_message(self, serialized_data):
        try:
            MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
            MajorLogRes.ParseFromString(serialized_data)
            key = MajorLogRes.ak
            iv = MajorLogRes.aiv
            if isinstance(key, bytes):
                key = key.hex()
            if isinstance(iv, bytes):
                iv = iv.hex()
            self.key = key
            self.iv = iv
            print(f"Key: {self.key} | IV: {self.iv}")
            return self.key, self.iv
        except Exception as e:
            print(f"{e}")
            return None, None

    def nmnmmmmn(self, data):
        key, iv = self.key, self.iv
        try:
            key = key if isinstance(key, bytes) else bytes.fromhex(key)
            iv = iv if isinstance(iv, bytes) else bytes.fromhex(iv)
            data = bytes.fromhex(data)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            cipher_text = cipher.encrypt(pad(data, AES.block_size))
            return cipher_text.hex()
        except Exception as e:
            print(f"Error in nmnmmmmn: {e}")

    def spam_room(self, idroom, idplayer):
        fields = {
        1: 78,
        2: {
            1: int(idroom),
            2: "Amdts Bot",
            4: 330,
            5: 6000,
            6: 201,
            10: int(get_random_avatar()),
            11: int(idplayer),
            12: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def send_squad(self, idplayer):
        fields = {
            1: 33,
            2: {
                1: int(idplayer),
                2: "VN",
                3: 1,
                4: 1,
                7: 330,
                8: 19459,
                9: 100,
                12: 1,
                16: 1,
                17: {
                2: 94,
                6: 11,
                8: "1.109.5",
                9: 3,
                10: 2
                },
                18: 201,
                23: {
                2: 1,
                3: 1
                },
                24: int(get_random_avatar()),
                26: {},
                28: {}
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def start_autooo(self):
        fields = {
        1: 9,
        2: {
            1: 12577368302
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def invite_skwad(self, idplayer):
        fields = {
        1: 2,
        2: {
            1: int(idplayer),
            2: "VN",
            4: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
        
    def join_squad_by_code(self, team_code, name="[C][B][00FF00]AmdtsModz"):
        fields = {
        1: 5,
        2: {
            1: int(team_code),       
            2: "Amdts",        
            3: 1,
            4: 1,
            7: 330,
            8: 19459,
            9: 100,
            12: 1,
            16: 1,
            17: {
            2: 94,
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
            18: 201,
            23: {
            2: 1,
            3: 1
            },
            24: int(get_random_avatar()),
            26: {},
            28: {}
        }
        }
        
    def request_skwad(self, idplayer):
        fields = {
        1: 33,
        2: {
            1: int(idplayer),
            2: "VN",
            3: 1,
            4: 1,
            7: 330,
            8: 19459,
            9: 100,
            12: 1,
            16: 1,
            17: {
            2: 94,
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
            18: 201,
            23: {
            2: 1,
            3: 1
            },
            24: int(get_random_avatar()),
            26: {},
            28: {}
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def skwad_maker(self):
        fields = {
        1: 1,
        2: {
            2: "\u0001",
            3: 1,
            4: 1,
            5: "en",
            9: 1,
            11: 1,
            13: 1,
            14: {
            2: 5756,
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def changes(self, num):
        fields = {
        1: 17,
        2: {
            1: 12577368302,
            2: 1,
            3: int(num),
            4: 62,
            5: "\u001a",
            8: 5,
            13: 329
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def leave_s(self):
        fields = {
        1: 7,
        2: {
            1: 12577368302
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def leave_room(self, idroom):
        fields = {
        1: 6,
        2: {
            1: int(idroom)
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def stauts_infoo(self, idd):
        fields = {
        1: 7,
        2: {
            1: 12577368302
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def GenResponsMsg(self, Msg, Enc_Id):
        fields = {
            1: 1,
            2: {
            1: 3557944186,
            2: Enc_Id,
            3: 2,
            4: str(Msg),
            5: int(datetime.now().timestamp()),
            9: {
            
            2: int(get_random_avatar()),
            3: 901050006,
            4: 330,
            
            10: 1,
            11: 155
            },
            10: "en",
            13: {
            1: "https://graph.facebook.com/v9.0/104076471965380/picture?width=160&height=160",
            2: 1,
            3: 1
            }
            },
            14: ""
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "1215000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "121500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "12150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "1215000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def createpacketinfo(self, idddd):
        ida = Encrypt(idddd)
        packet = f"080112090A05{ida}1005"
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0F15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0F1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0F150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0F15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def accept_sq(self, hashteam, idplayer, ownerr):
        fields = {
        1: 4,
        2: {
            1: int(ownerr),
            3: int(idplayer),
            4: "\u0001\u0007\t\n\u0012\u0019\u001a ",
            8: 1,
            9: {
            2: 1393,
            4: "AmdtsModz",
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
            10: hashteam,
            12: 1,
            13: "en",
            16: "OR"
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def info_room(self, idrooom):
        fields = {
        1: 1,
        2: {
            1: int(idrooom),
            3: {},
            4: 1,
            6: "en"
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def sockf1(self, tok, online_ip, online_port, packet, key, iv):
        global socket_client
        global sent_inv
        global tempid
        global start_par
        global clients
        global pleaseaccept
        global tempdata1
        global nameinv
        global idinv
        global senthi
        global statusinfo
        global tempdata
        global data22
        global leaveee
        global isroom
        global isroom2
        socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        online_port = int(online_port)

        socket_client.connect((online_ip,online_port))
        print(f" Con port {online_port} Host {online_ip} ")
        print(tok)
        socket_client.send(bytes.fromhex(tok))
        while True:
            data2 = socket_client.recv(9999)
            print(data2)
            if "0500" in data2.hex()[0:4]:
                accept_packet = f'08{data2.hex().split("08", 1)[1]}'
                kk = get_available_room(accept_packet)
                parsed_data = json.loads(kk)
                fark = parsed_data.get("4", {}).get("data", None)
                if fark is not None:
                    print(f"haaaaaaaaaaaaaaaaaaaaaaho {fark}")
                    if fark == 18:
                        if sent_inv:
                            accept_packet = f'08{data2.hex().split("08", 1)[1]}'
                            print(accept_packet)
                            print(tempid)
                            aa = gethashteam(accept_packet)
                            ownerid = getownteam(accept_packet)
                            print(ownerid)
                            print(aa)
                            ss = self.accept_sq(aa, tempid, int(ownerid))
                            socket_client.send(ss)
                            sleep(1)
                            startauto = self.start_autooo()
                            socket_client.send(startauto)
                            start_par = False
                            sent_inv = False
                    if fark == 6:
                        leaveee = True
                        print("kaynaaaaaaaaaaaaaaaa")
                    if fark == 50:
                        pleaseaccept = True
                print(data2.hex())

            if "0600" in data2.hex()[0:4] and len(data2.hex()) > 700:
                    accept_packet = f'08{data2.hex().split("08", 1)[1]}'
                    kk = get_available_room(accept_packet)
                    parsed_data = json.loads(kk)
                    print(parsed_data)
                    idinv = parsed_data["5"]["data"]["1"]["data"]
                    nameinv = parsed_data["5"]["data"]["3"]["data"]
                    senthi = True
            if "0f00" in data2.hex()[0:4]:
                packett = f'08{data2.hex().split("08", 1)[1]}'
                print(packett)
                kk = get_available_room(packett)
                parsed_data = json.loads(kk)
                
                asdj = parsed_data["2"]["data"]
                tempdata = get_player_status(packett)
                if asdj == 15:
                    if tempdata == "OFFLINE":
                        tempdata = f"The id is {tempdata}"
                    else:
                        idplayer = parsed_data["5"]["data"]["1"]["data"]["1"]["data"]
                        idplayer1 = fix_num(idplayer)
                        if tempdata == "IN ROOM":
                            idrooom = get_idroom_by_idplayer(packett)
                            idrooom1 = fix_num(idrooom)
                            
                            tempdata = f"id : {idplayer1}\nstatus : {tempdata}\nid room : {idrooom1}"
                            data22 = packett
                            print(data22)
                            
                        if "INSQUAD" in tempdata:
                            idleader = get_leader(packett)
                            idleader1 = fix_num(idleader)
                            tempdata = f"id : {idplayer1}\nstatus : {tempdata}\nleader id : {idleader1}"
                        else:
                            tempdata = f"id : {idplayer1}\nstatus : {tempdata}"
                    statusinfo = True 

                    print(data2.hex())
                    print(tempdata)
                
                    

                else:
                    pass
            if "0e00" in data2.hex()[0:4]:
                packett = f'08{data2.hex().split("08", 1)[1]}'
                print(packett)
                kk = get_available_room(packett)
                parsed_data = json.loads(kk)
                idplayer1 = fix_num(idplayer)
                asdj = parsed_data["2"]["data"]
                tempdata1 = get_player_status(packett)
                if asdj == 14:
                    nameroom = parsed_data["5"]["data"]["1"]["data"]["2"]["data"]
                    
                    maxplayer = parsed_data["5"]["data"]["1"]["data"]["7"]["data"]
                    maxplayer1 = fix_num(maxplayer)
                    nowplayer = parsed_data["5"]["data"]["1"]["data"]["6"]["data"]
                    nowplayer1 = fix_num(nowplayer)
                    tempdata1 = f"{tempdata}\nRoom name : {nameroom}\nMax player : {maxplayer1}\nLive player : {nowplayer1}"
                    print(tempdata1)
                    

                    
                
                    
            if data2 == b"":
                
                print("Connection closed by remote host")
                restart_program()
                break
    
    
    def connect(self, tok, packet, key, iv, whisper_ip, whisper_port, online_ip, online_port):
        global clients
        global socket_client
        global sent_inv
        global tempid
        global leaveee
        global start_par
        global nameinv
        global idinv
        global senthi
        global statusinfo
        global tempdata
        global pleaseaccept
        global tempdata1
        global data22
        clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clients.connect((whisper_ip, whisper_port))
        clients.send(bytes.fromhex(tok))
        thread = threading.Thread(
            target=self.sockf1, args=(tok, online_ip, online_port, "anything", key, iv)
        )
        threads.append(thread)
        thread.start()

        while True:
            data = clients.recv(9999)

            if data == b"":
                print("Connection closed by remote host")
                break
                print(f"Received data: {data}")
            
            if senthi == True:
                
                clients.send(
                        self.GenResponsMsg(
                            f"""
[C][B][FFFFFF]Xin chào Bé Yêu

Cảm Ơn Bạn Đã Chấp Nhận Y[c]ê[c]u C[c]ầ[c]u K[c]ế[c]t B[c]ạ[c]n Của Mình

[C][B][FFFFFF]Bạn Còn Chờ Đợi Cái Gì Hãy Gửi Cho Bot 1 icon Bất Kì Để Biết Bạn Sẽ Phải Làm Gì Tiếp Nhé

[C][B][FF0000]Mọi vấn đề về bot li[c]ê[c]n h[c]ệ qua:
[C][B][FFFFFF]T[c]e[c]le[c]g[c]r[c]a[c]m: [C][B][11EAFD]@cdanhdev

[C][B][FF0000]Mọi vấn đề về bot li[c]ê[c]n h[c]ệ qua:
[C][B][FFFFFF]Facebook: [C][B][11EAFD]Danh Lê""", idinv
                        )
                )
                senthi = False
            
            
            
            if "1200" in data.hex()[0:4]:
               
                json_result = get_available_room(data.hex()[10:])
                print(data.hex())
                parsed_data = json.loads(json_result)
                try:
	                user_name = parsed_data['5']['data']['9']['data']['1']['data']
	                uid = parsed_data["5"]["data"]["1"]["data"]          
                    
                except KeyError:
                    print("Warning: '1' key is missing in parsed_data, skipping...")
                    uid = None  
                if "8" in parsed_data["5"]["data"] and "data" in parsed_data["5"]["data"]["8"]:
                    uexmojiii = parsed_data["5"]["data"]["8"]["data"]
                    if uexmojiii == "DefaultMessageWithKey":
                        pass
                    else:
                        clients.send(
                            self.GenResponsMsg(
                            f"""
[C][B][FFFFFF]Xin chào Bé Yêu {user_name}
mình là [C][B][00FFFF]cdanhdev

[C][B][FFFFFF]Bạn Còn Chờ Đợi Cái Gì Hãy Gõ [FF0000]/🗿help[FFFFFF] Để Xem Menu Lệnh Của Bot

[C][B][FF0000]Mọi vấn đề về bot li[c]ê[c]n h[c]ệ qua:
[C][B][FFFFFF]Facebook: [C][B][11EAFD]Danh Lê

[C][B][007AFF]L[C][B][339BFF]o[C][B][66BBFF]a[C][B][99DFFF]n[C][B][CCF5FF] Đ[C][B][E0FAFF]à[C][B][F0FDFF]m""",uid
                            )
                        )

            if "1200" in data.hex()[0:4] and b"/giabot" in data:
                i = re.split("giabot", str(data))[1]
                if "***" in i:
                    i = i.replace("***", "106")
                sid = str(i).split("(\\x")[0]
                json_result = get_available_room(data.hex()[10:])
                
                parsed_data = json.loads(json_result)
                user_name = parsed_data['5']['data']['9']['data']['1']['data']
                uid = parsed_data["5"]["data"]["1"]["data"]
               

                clients.send(
                    self.GenResponsMsg(
                        f""" 
[b][c][FFFFFF]Xin Chào [11EAFD]{user_name} 
[FFFFFF]Dưới Đây Là Bảng Giá Thuê Bot

1 Ngày 5 Nghìn VND 
1 Tuần 25 Nghìn VND
1 Tháng 130 Nghìn VND
1 năm 800 Nghìn VND

""", uid
                    )
                )


            if "1200" in data.hex()[0:4] and b"/hed" in data:
                import re
                try:

                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    sender_id = parsed_data["5"]["data"]["1"]["data"]
            
                    ok, reason = is_user_allowed(sender_id)
                    if not ok:
                        clients.send(self.GenResponsMsg(f"[C][B][FF0000]❌ {reason}", sender_id))
                    else:

                        command_split = re.split("/hed", str(data))
                        if len(command_split) > 1:
                            i = command_split[1]
                            if "***" in i:
                                i = i.replace("***", "106")
            
                            sid = i.split("(\\x")[0].strip()
            
                            uid = sender_id
                            clients.send(
                                self.GenResponsMsg(
                                    f"""
━━━━━━━━━━━
[00FF00][C][B] /🤔tx [tai|xiu] [số cược]
[00FF00][C][B] /🤔dd ➝ [FFFFFF]Điểm danh nhận xu
[00FF00][C][B] /🤔top ➝ [FFFFFF]Top người chơi
[00FF00][C][B] /🤔giabot ➝ [FFFFFF]Xem giá bot
━━━━━━━━━━━""",
                                    uid
                                )
                            )
            
                except Exception as e:
                    print(f"Error in /hed command: {e}")
            

            if "1200" in data.hex()[0:4] and b"/sf" in data:
                import re
                try:
                    command_split = re.split("/sf ", str(data))
                    if len(command_split) > 1:
                        player_id = command_split[1].split('(')[0].strip()
                        if "***" in player_id:
                            player_id = player_id.replace("***", "106")
                            
                            
                            
                    
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        clients.send(
                            self.GenResponsMsg(
                                f"[b][c]S[c]p[c]a[c]m Tổ Đội [b][c]FREE F[FF8800]I[FFFFFF]RE[FF8800]\n\nGửi Đến UID: {fix_num(player_id)}\n Số Lượng: 20 Y[c]ê[c]u C[c]ầ[c]u!!!\n"                              , uid
                            )
                        )                            

                        
                        json_result = get_available_room(data.hex()[10:])
                        
                        parsed_data = json.loads(json_result)

                        tempid = player_id
                        
                        def send_invite():
                            invskwad = self.request_skwad(player_id)
                            socket_client.send(invskwad)                         

                       


                        threadss = []
                        for _ in range(30):
                            thread = threading.Thread(target=send_invite)
                            thread.start()
                            threadss.append(thread)                                                        
                        
                        for thread in threadss:
                            thread.join()

                        sent_inv = True

                    
                    
                      
                except Exception as e:
                    print(f"Error in /md command: {e}")


            if "1200" in data.hex()[0:4] and b"/+user" in data:
                import re
                from datetime import datetime, timedelta
                try:
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    sender_id = parsed_data["5"]["data"]["1"]["data"]
            
                    
                    if str(sender_id) not in ADMIN_UID:
                        clients.send(
                            self.GenResponsMsg(
                                "[C][B][FF0000]@cdanhdev:\n\n[C][B][C0C0C0]Lệnh này của admin",
                                sender_id
                            )
                        )
                        return
            
                    raw_message = data.decode('utf-8', errors='ignore')
                    match = re.search(r'/\+user\s+(\d{5,15})\s+(\d+)d', raw_message)
            
                    if not match:
                        clients.send(self.GenResponsMsg(
                            "[C][B][FF0000]❌ Lệnh sai định dạng. Ví dụ đúng: /+user 12345 1d",
                            sender_id
                        ))
                        return
            
                    target_uid = match.group(1)
                    days = int(match.group(2))
            
                    expire_datetime = add_days(target_uid, days)
                    expire_str = expire_datetime.strftime("%d/%m/%Y %H:%M:%S")
                    expire_date, expire_time = expire_str.split(" ")
            
                    message_text = (
                        "\n[C][B][FF0000]USER INFO [b][c][FFFFFF]FREE F[FF8800]I[FFFFFF]RE[FF8800]:\n\n"
                        f"[C][B][FF0000]❌ UID: [C0C0C0]{insert_c_marker(target_uid)}\n"
                        f"[C][B][FF0000]❌ Số Ngày: [C0C0C0]{insert_c_marker(expire_date)}\n"
                        f"[C][B][FF0000]❌ Số Giờ: [C0C0C0]{insert_c_marker(expire_time)}\n\n"
                        f"[b][ffffff]T[c]e[c]le[c]g[c]r[c]a[c]m: [b][c][11EAFD]@cdanhdev\n" 
                    )
                    clients.send(self.GenResponsMsg(message_text, sender_id))
            
                except Exception as e:
                    clients.send(self.GenResponsMsg(
                        f"[C][B][FF0000]❌ Lỗi xử lý lệnh: {str(e)}",
                        sender_id
                    )
                    )

            if "1200" in data.hex()[0:4] and b"/ai" in data:
                    import re
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data["5"]["data"]["1"]["data"]


                    command_split = re.split(r"/ai", str(data))
                    if "***" in command_split[1]:
                        command_split[1] = command_split[1].replace("***", "106")

                    sid = str(command_split[1]).split("(\\x")[0].strip()
                    tinnhan = sid

                    print(f"[AI CMD] From UID {uid} | Msg: {tinnhan}")

                    headers = {"Content-Type": "application/json"}
                    response = requests.post(
                        f"http://dinhhoang.x10.mx/amdts.php?tinnhan={tinnhan}",
                        headers=headers,
                        verify=False
                    )

                    if response.status_code == 200:
                        ai_data = response.json()
                        if ai_data.get("status") == "success" and "answer" in ai_data:
                            ai_response = ai_data["answer"]
                            clients.send(self.GenResponsMsg(ai_response, uid))
                        else:
                            print("Lỗi phản hồi AI:", ai_data)
                            clients.send(self.GenResponsMsg("Bot lỗi, thử lại sau", uid))
                    else:
                        print("Error with AI API:", response.status_code, response.text)
                        clients.send(self.GenResponsMsg("API không phản hồi!", uid))

                        

            if "1200" in data.hex()[0:4] and b"/-user" in data:
                import re
                from datetime import datetime, timedelta
                try:
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    sender_id = parsed_data["5"]["data"]["1"]["data"]
            
                    
                    if str(sender_id) not in ADMIN_UID:
                        clients.send(
                            self.GenResponsMsg(
                                "[C][B][FF0000]@cdanhdev:\n\n[C][B][C0C0C0]Lệnh này của admin",
                                sender_id
                            )
                        )
                        return
            
                    raw_message = data.decode('utf-8', errors='ignore')
                    match = re.search(r'/\-user\s+(\d{5,15})\s+(\d+)d', raw_message)
            
                    if not match:
                        clients.send(self.GenResponsMsg(
                            "[C][B][FF0000]❌ Lệnh sai định dạng. Ví dụ đúng: /+user 12345 1d",
                            sender_id
                        ))
                        return
            
                    target_uid = match.group(1)
                    days = int(match.group(2))
            
                    expire_datetime = add_days(target_uid, days)
                    expire_str = expire_datetime.strftime("%d/%m/%Y %H:%M:%S")
                    expire_date, expire_time = expire_str.split(" ")
            
                    # Gửi lời mời kết bạn
                    with open("token.txt", "r") as f:
                        jwt_token = f.read().strip()
                    amdtsmodz.RequestAddingFriend(3975170787, target_uid, jwt_token)
            
                    # Gửi thông tin gộp
                    message_text = (
                        "\n[C][B][FF0000]A[c]D[c]D VIP USER INFO:\n\n"
                        f"[C][B][FF0000]UID: [C0C0C0]{fix_num(target_uid)}\n"
                        f"[C][B][FF0000]Số Ngày: [C0C0C0]{insert_c_marker(expire_date)}\n"
                        f"[C][B][FF0000]Số Giờ: [C0C0C0]{insert_c_marker(expire_time)}\n"
                        f"[C][B][FF0000]Trạng Thái: [00FF00]Đ[c]ã G[c]ử[c]i L[c]ờ[c]i M[c]ờ[c]i K[c]ế[c]t B[c]ạ[c]n\n\n"
                        f"[b][ffffff]T[c]e[c]le[c]g[c]r[c]a[c]m: [b][c][11EAFD]@cdanhdev\n"
                    )
                    clients.send(self.GenResponsMsg(message_text, sender_id))
            
                except Exception as e:
                    clients.send(self.GenResponsMsg(
                        f"[C][B][FF0000]❌ Lỗi xử lý lệnh: {str(e)}",
                        sender_id
                    ))
            if b"/deluser" in data:
                import re
                try:
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    sender_id = parsed_data["5"]["data"]["1"]["data"]
            
                    # Check quyền admin
                    if str(sender_id) not in ADMIN_UID:
                        clients.send(
                            self.GenResponsMsg(
                                "[C][B][FF0000]Bạn không có quyền dùng lệnh này!",
                                sender_id
                            )
                        )
                        return
            
                    raw_message = data.decode('utf-8', errors='ignore')
                    match = re.search(r'/del\s+(\d+)', raw_message)
            
                    if not match:
                        clients.send(self.GenResponsMsg(
                            "[C][B][FF0000]Sai cú pháp! Dùng: /del <uid>",
                            sender_id
                        ))
                        return
            
                    target_uid = match.group(1)
            
                    try:
                        with open("allowed_users.json", "r", encoding="utf-8") as f:
                            data_vip = json.load(f)
                    except FileNotFoundError:
                        data_vip = {}
            
                    if target_uid in data_vip:
                        del data_vip[target_uid]
                        with open("allowed_users.json", "w", encoding="utf-8") as f:
                            json.dump(data_vip, f, indent=4, ensure_ascii=False)
                        clients.send(self.GenResponsMsg(
                            f"[C][B][00FF00]Đã xóa UID: {target_uid} khỏi danh sách VIP!",
                            sender_id
                        ))
                    else:
                        clients.send(self.GenResponsMsg(
                            f"[C][B][FF0000]UID {target_uid} không tồn tại trong danh sách VIP!",
                            sender_id
                        ))
            
                except Exception as e:
                    clients.send(self.GenResponsMsg(
                        f"[C][B][FF0000]Lỗi xử lý: {str(e)}",
                        sender_id
                    ))

                    
                    
            if "1200" in data.hex()[0:4] and b"/st" in data:
                import re
                try:
                    # ✅ Lấy UID người gửi để check quyền
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    sender_id = parsed_data["5"]["data"]["1"]["data"]
            
                    ok, reason = is_user_allowed(sender_id)
                    if not ok:
                        clients.send(self.GenResponsMsg(f"[C][B][FF0000]❌ {reason}", sender_id))
                    else:
                        
                        command_split = re.split("/st ", str(data))
                        if len(command_split) > 1:
                            player_id = command_split[1].split('(')[0].strip()
                            if "***" in player_id:
                                player_id = player_id.replace("***", "106")
            
                            uid = sender_id
                            clients.send(
                                self.GenResponsMsg(
                                    f"[b][c]S[c]p[c]a[c]m Tổ Đội [b][c]FREE F[FF8800]I[FFFFFF]RE[FF8800]\n\n"
                                    f"Gửi Đến UID: \n Số Lượng: 20 Y[c]ê[c]u C[c]ầ[c]u!!!\n", uid
                                )
                            )
            
                            tempid = player_id
            
                            def send_invite():
                                invskwad = self.request_skwad(player_id)
                                socket_client.send(invskwad)
            
                            threadss = []
                            for _ in range(30):
                                thread = threading.Thread(target=send_invite)
                                thread.start()
                                threadss.append(thread)
            
                            for thread in threadss:
                                thread.join()
            
                            sent_inv = True
            
                except Exception as e:
                    print(f"Error in /md command: {e}")
    
                                
            import re
            import json
            from time import sleep
            
            if "1200" in data.hex()[0:4] and b"/3" in data:
                try:

                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    sender_id = parsed_data["5"]["data"]["1"]["data"]
            
                    ok, reason = is_user_allowed(sender_id)
                    if not ok:
                        clients.send(self.GenResponsMsg(f"[C][B][FF0000]❌ {reason}", sender_id))
                    else:

                        i = re.split("/3", str(data))[1]
                        if "***" in i:
                            i = i.replace("***", "106")
                        sid = str(i).split("(\\x")[0]
            
                        uid = sender_id
            

                        packetmaker = self.skwad_maker()
                        socket_client.send(packetmaker)
                        sleep(0.5)
            

                        packetfinal = self.changes(2)
                        socket_client.send(packetfinal)
                        sleep(0.5)
            

                        room_data = None
                        if b'(' in data:
                            split_data = data.split(b'/3')
                            if len(split_data) > 1:
                                room_data = split_data[1].split(b'(')[0].decode().strip().split()
                                if room_data:
                                    iddd = room_data[0]
                                else:
                                    iddd = uid
                        else:
                            iddd = uid
            
                        invitess = self.invite_skwad(iddd)
                        socket_client.send(invitess)
            

                        clients.send(
                            self.GenResponsMsg(
                                f"[FFFFFF][b][c]Đã Tạo Thành Công\nTeam 3\n[ffffff]Hãy Chấp Nhận L[c]ờ[c]i Mời Bot Gửi",
                                uid
                            )
                        )
            

                        sleep(5)
                        leavee = self.leave_s()
                        socket_client.send(leavee)
                        sleep(1)
                        change_to_solo = self.changes(1)
                        socket_client.send(change_to_solo)
            
                except Exception as e:
                    print(f"Error in /3 command: {e}")
  
            if "1200" in data.hex()[0:4] and b"/xkb" in data:
                import re
                try:
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    sender_id = parsed_data["5"]["data"]["1"]["data"]
            

                    if str(sender_id) not in ADMIN_UID:
                        clients.send(
                            self.GenResponsMsg(
                                "[C][B][FF0000]@cdanhdev:\n\n[C][B][C0C0C0]Bạn không có quyền sử dụng lệnh này!",
                                sender_id
                            )
                        )
                        return
            
                    raw_message = data.decode('utf-8', errors='ignore')
                    match = re.search(r'/xkb\s+(\d{5,15})', raw_message)
            
                    if not match:
                        clients.send(self.GenResponsMsg(
                            "[C][B][FF0000]❌ Sai định dạng. Ví dụ đúng: /xkb 123456789",
                            sender_id
                        ))
                        return
            
                    target_uid = match.group(1)
            

                    with open("token.txt", "r") as f:
                        jwt_token = f.read().strip()
            

                    xoakb = Xoakb()
                    xoakb.RemoveFriend(sender_id, target_uid, jwt_token)
            

                    message_text = (
                        "[C][B][FF0000]Remove Friend\n\n"
                        f"[C][B] » UID: [C0C0C0]{fix_num(target_uid)}\n"
                        f"[FFFFFF]× Trạng Thái: [00FF00]Remove To Friend thành công"
                    )
                    clients.send(self.GenResponsMsg(message_text, sender_id))
            
                except Exception as e:
                    clients.send(self.GenResponsMsg(
                        f"[C][B][FF0000]❌ Lỗi xử lý lệnh: {str(e)}",
                        sender_id
                    ))
                    
            if "1200" in data.hex()[0:4] and b"/info" in data:
	                try:
	                    print("✅ /info command detected.")  
	                    command_split = re.split("/info", str(data))

	                    if len(command_split) <= 1 or not command_split[1].strip():  # ✅ إذا لم يتم إدخال ID
	                        print("❌ No ID provided, sending error message.")
	                        json_result = get_available_room(data.hex()[10:])
	                        parsed_data = json.loads(json_result)
	                        sender_id = parsed_data["5"]["data"]["1"]["data"]
	                        clients.send(self.GenResponsMsg("[C][B][FF0000] Please enter [00FF00َ]a valid[6E00FFَ] player [FFFF00ِ]ID!", sender_id))
	                        
	                    else:
	                        print("✅ Command has parameters.")  
	                        json_result = get_available_room(data.hex()[10:])
	                        parsed_data = json.loads(json_result)

	                        sender_id = parsed_data["5"]["data"]["1"]["data"]
	                        sender_name = parsed_data['5']['data']['9']['data']['1']['data']
	                        print(f"✅ Sender ID: {sender_id}, Sender Name: {sender_name}")  

	                        # ✅ استخراج UID الصحيح فقط
	                        uids = re.findall(r"\b\d{5,15}\b", command_split[1])  # استخراج أول رقم بين 5 و 15 رقمًا
	                        uid = uids[0] if uids else ""  # ✅ أخذ أول UID فقط

	                        if not uid:
	                            print("❌ No valid UID found, sending error message.")
	                            clients.send(self.GenResponsMsg("[C][B][FF0000] Invalid Player ID!", sender_id))
	                            
	                        else:
	                            print(f"✅ Extracted UID: {uid}")  

	                            try:
	                                info_response = newinfo(uid)
	                                print(f"✅ API Response Received: {info_response}")  
	                            except Exception as e:
	                                print(f"❌ API Error: {e}")
	                                clients.send(self.GenResponsMsg("[C][B] [FF0000] Server Error, Try Again!", sender_id))
	                                
	                            if 'info' not in info_response or info_response['status'] != "ok":
	                                print("❌ Invalid ID or API Error, sending wrong ID message.")
	                                clients.send(self.GenResponsMsg("[C][B] [FF0000] Wrong ID .. Please Check Again", sender_id))
	                                
	                            else:
	                                print("✅ Valid API Response, Extracting Player Info.")  
	                                infoo = info_response['info']
	                                basic_info = infoo['basic_info']
	                                clan_info = infoo.get('clan_info', "false")
	                                clan_admin = infoo.get('clan_admin', {})

	                                if clan_info == "false":
	                                    clan_info_text = "\nPlayer Not In Clan\n"
	                                else:
	                                    clan_info_text = (
	                                        f"00FF00][C][B]Clan Info :\n"
	                                        f"00FF00][C][B] Clan ID : {fix_num(clan_info['clanid'])}\n"
	                                        f"[B][FFA500]• Name: [FFFFFF]{clan_info.get('clanname', 'N/A')}\n"
	                                        f"[B][FFA500]• Members: [FFFFFF]{clan_info.get('livemember', 0)}\n"
	                                        f"[B][FFA500]• Level: [FFFFFF]{clan_info.get('guildlevel', 0)}\n"
	                                       f"[C][B][00FF00]━━━━━━━━━━━━━\n"
	                                         
	                                        
	                                    )

	                                level = basic_info['level']
	                                likes = basic_info['likes']
	                                name = basic_info['username']
	                                region = basic_info['region']
	                                bio = basic_info.get('bio', "No bio available").replace("|", " ")
	                                br_rank = fix_num(basic_info['brrankscore'])
	                                exp = fix_num(basic_info['Exp'])

	                                print(f"✅ Player Info Extracted: {name}, Level: {level}, Region: {region}")

	                                message_info = (
	                                    f"[C][B][00FF00]━━━━━━━━━━━━━\n"
    f"[B][FFA500]• Name: [FFFFFF]{name}\n"
    f"[B][FFA500]• Level: [FFFFFF]{level}\n"
    f"[B][FFA500]• Server: [FFFFFF]{region}\n"
    f"[B][FFA500]• Likes: [FFFFFF]{fix_num(likes)}\n"
    f"[B][FFA500]• Bio: [FFFFFF]{bio}\n"
	                          
	                                 f"{clan_info_text}\n"
	                                    
	                                )

	                                print(f"📤 Sending message to game: {message_info}")  

	                                try:
	                                    clients.send(self.GenResponsMsg(message_info, sender_id))
	                                    print("✅ Message Sent Successfully!")  
	                                except Exception as e:
	                                    print(f"❌ Error sending message: {e}")
	                                    clients.send(self.GenResponsMsg("[C][B] [FF0000] Failed to send message!", sender_id))

	                except Exception as e:
	                    print(f"❌ Unexpected Error: {e}")
	                    clients.send(self.GenResponsMsg("[C][B][FF0000] An unexpected error occurred!", sender_id))
             
            if "1200" in data.hex()[0:4] and b"/like/" in data:
                
                try:
                     
                    raw_message = data.decode('utf-8', errors='ignore')
                    cleaned_message = raw_message.replace('\x00', '').strip()
                    
                    
                    default_id = "2060437760"
                    player_id = default_id
                    
                    try:
                        id_match = re.search(r'/like/(\d{5,15})\b', cleaned_message)
                        
                        if id_match:
                            player_id = id_match.group(1)
                             
                            if not (5 <= len(player_id) <= 15) or not player_id.isdigit():
                                player_id = default_id
                        else:                             
                            temp_id = cleaned_message.split('/like/')[1].split()[0].strip()
                            player_id = temp_id if temp_id.isdigit() and len(temp_id) >= 5 else default_id
                            
                    except Exception as e:
                        print(f"Likes ID extraction error: {e}")
                        player_id = default_id               
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data["5"]["data"]["1"]["data"]
                    clients.send(self.GenResponsMsg("Đang buff nè...", uid))
                    
                    likes_info = send_likes(player_id)
                    player_id = fix_num(player_id)
                    clients.send(self.GenResponsMsg(likes_info, uid))
            
                except Exception as e:
                    print(f"Likes Command Error: {e}")
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        error_msg = f"[FF0000]mistake: {e}" if "ID" in str(e) else f"[FF0000]Likes error: {e}"
                        clients.send(self.GenResponsMsg(error_msg, uid))
                    except:
                        restart_program()
  
            if "1200" in data.hex()[0:4] and b"/help" in data:
                import time
                lines = "_" * 20
            
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                user_name = parsed_data['5']['data']['9']['data']['1']['data']
                uid = parsed_data["5"]["data"]["1"]["data"]
                if "***" in str(uid):
                    uid = rrrrrrrrrrrrrr(uid)  
            
                ok, reason = is_user_allowed(uid)
                if not ok:
                    clients.send(self.GenResponsMsg(f"[C][B][FF0000]❌ {reason}", uid))
                else:

                    vip_info = get_vip_info(uid)
                    role = vip_info["role"]
                    days = vip_info["days"]
                    hours = vip_info["hours"]
                    minutes = vip_info["minutes"]
                    seconds = vip_info["seconds"]
            
                    print(f"\nUser With ID : {uid}\nName : {user_name}\nStarted Help\n")
            
                    time.sleep(0.3)
                    clients.send(
                        self.GenResponsMsg(
                            f"""                   [C][B][FFFFFF]FREE F[C][B][FF8800]I[C][B][FFFFFF]RE

[C][B][FFFFFF]👋 Xin chào Bé Yêu {user_name}  

━━━━━━━━━━━━━
[00FF00][C][B] /🤔like/[id] ➝ [FFFFFF]Tăng likes
[00FF00][C][B] /🤔3, 5, 6 ➝ [FFFFFF]Team 3 ➝ 6  
[00FF00][C][B] /🤔crt [id] ➝ [FFFFFF]Mời 1 người chơi
[00FF00][C][B] /🤔sp [id] ➝ [FFFFFF]Spam join phòng  
[00FF00][C][B] /🤔atk (team code) ➝ [FFFFFF]Tron lag  
━━━━━━━━━━━━━
            """, uid
                        )
                    )
                    time.sleep(0.3)
                    clients.send(
                        self.GenResponsMsg(
		                        f"""━━━━━━━━━━━━
[00FF00][C][B] /🤔start [id] ➝ [FFFFFF]Ép đội vào trận 
[00FF00][C][B] /🤔giabot [id] ➝ [FFFFFF]Xem Giá Bot
[00FF00][C][B] /🤔come (team code) ➝ [FFFFFF]bot vào đội  
[00FF00][C][B] /🤔solo ➝ [FFFFFF]Bot rời đội  
[00FF00][C][B] /🤔ai [văn bản] ➝ [FFFFFF]Hỏi Chat GPT
━━━━━━━━━━━━━
            """, uid
                        )
                    )
                    time.sleep(0.3)
                    clients.send(
                        self.GenResponsMsg(
                            f"""
           [C][B][ffffff] User Info Players

[C][B][FFFFFF]× Name: [C0C0C0]{user_name}

[C][B][FFFFFF]× Roles: [C0C0C0]{role}

[C][B][FFFFFF]× Ngày: [C0C0C0]{days} Ngày

[C][B][FFFFFF]× Giờ: [C0C0C0]{hours} Giờ {minutes} Phút {seconds} Giây

[b][ffffff]T[c]e[c]le[c]g[c]r[c]a[c]m: [b][c][11EAFD]@cdanhdev
            """, uid
                        )
                    )


            if "1200" in data.hex()[0:4] and b"/5" in data:
                try:

                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    sender_id = parsed_data["5"]["data"]["1"]["data"]
            
                    ok, reason = is_user_allowed(sender_id)
                    if not ok:
                        clients.send(self.GenResponsMsg(f"[C][B][FF0000]❌ {reason}", sender_id))
                    else:

                        i = re.split("/5", str(data))[1]
                        if "***" in i:
                            i = i.replace("***", "106")
                        sid = str(i).split("(\\x")[0]
            
                        uid = sender_id
            

                        packetmaker = self.skwad_maker()
                        socket_client.send(packetmaker)
                        sleep(0.5)  
            

                        packetfinal = self.changes(4)
                        socket_client.send(packetfinal)
                        sleep(0.5)
            

                        room_data = None
                        if b'(' in data:
                            split_data = data.split(b'/5')
                            if len(split_data) > 1:
                                room_data = split_data[1].split(b'(')[0].decode().strip().split()
                                if room_data:
                                    iddd = room_data[0]
                                else:
                                    iddd = uid
                        else:
                            iddd = uid
            
                        invitess = self.invite_skwad(iddd)
                        socket_client.send(invitess)
            

                        clients.send(
                            self.GenResponsMsg(
                                f"[FFFFFF][b][c]Đã Tạo Thành Công Team 5\n[ffffff]Hãy Chấp Nhận L[c]ờ[c]i Mời Bot Gửi",
                                uid
                            )
                        )
            

                        sleep(5)
                        leavee = self.leave_s()
                        socket_client.send(leavee)
                        sleep(1)
                        change_to_solo = self.changes(1)
                        socket_client.send(change_to_solo)
            
                except Exception as e:
                    print(f"Error in /5 command: {e}")


            if "1200" in data.hex()[0:4] and b"/team" in data:
                                # Tách sid (id của squad)
                                try:
                                                sid = re.split("/team", str(data))[1].split("(\\x")[0]
                                except:
                                                sid = "106"  # fallback an toàn

                                # Các mode an toàn
                                safe_modes = [2, 3, 4]

                                # Chọn chế độ khởi đầu ngẫu nhiên
                                first_mode = random.choice(safe_modes)

                                # Mời team vào chế độ random đầu tiên
                                socket_client.send(self.changes(first_mode, sid))

                                print(f"[Bot] Đã tạo team ở mode {first_mode}, bắt đầu đổi chế độ liên tục ...")

                                # Spam đổi mode liên tục nhưng không out nhóm
                                while True:
                                                for mode in safe_modes:
                                                                socket_client.send(self.changes(mode, sid))
                                                                time.sleep(random.uniform(0.3, 0.6))
            

            if "1200" in data.hex()[0:4] and b"/status" in data:
                try:
                    print("Received /st command")
                    i = re.split("/status", str(data))[1]
                    if "***" in i:
                        i = i.replace("***", "106")
                    sid = str(i).split("(\\x")[0]
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    split_data = re.split(rb'/status', data)
                    room_data = split_data[1].split(b'(')[0].decode().strip().split()
                    if room_data:
                        player_id = room_data[0]
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        packetmaker = self.createpacketinfo(player_id)
                        socket_client.send(packetmaker)
                        statusinfo1 = True
                        while statusinfo1:
                            if statusinfo == True:
                                if "IN ROOM" in tempdata:
                                    inforoooom = self.info_room(data22)
                                    socket_client.send(inforoooom)
                                    sleep(0.5)
                                    clients.send(self.GenResponsMsg(f"{tempdata1}", uid))  
                                    tempdata = None
                                    tempdata1 = None
                                    statusinfo = False
                                    statusinfo1 = False
                                else:
                                    clients.send(self.GenResponsMsg(f"{tempdata}", uid))  
                                    tempdata = None
                                    tempdata1 = None
                                    statusinfo = False
                                    statusinfo1 = False
                    else:
                        clients.send(self.GenResponsMsg("[C][B][FF0000] الرجاء إدخال معرف اللاعب!", uid))  
                except Exception as e:
                    print(f"Error in /rs command: {e}")
                    clients.send(self.GenResponsMsg("[C][B][FF0000]ERROR!", uid))
                
             
            if "1200" in data.hex()[0:4] and b"/crt" in data:
                import re
                try:
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    sender_id = parsed_data["5"]["data"]["1"]["data"]
            
                    ok, reason = is_user_allowed(sender_id)
                    if not ok:
                        clients.send(self.GenResponsMsg(f"[C][B][FF0000]❌ {reason}", sender_id))
                    else:
                        i = re.split("/crt", str(data))[1]
                        if "***" in i:
                            i = i.replace("***", "106")
                        sid = str(i).split("(\\x")[0]
            
                        uid = sender_id
            
                        split_data = re.split(rb'/crt', data)
                        room_data = split_data[1].split(b'(')[0].decode().strip().split()
                        if room_data:
                            print(room_data)
                            iddd = room_data[0]
                            numsc1 = "5"
            
                            if numsc1 is None:
                                clients.send(
                                    self.GenResponsMsg(
                                        f"[C][B] [FF00FF]Vui Lòng Nhập UID Người Muốn Mời Với Số Lượng Thành Viên\n[ffffff]Ví Dụ : \n/ inv 125[c]773[c]683[c]02 4\n/ inv 125[c]773[c]683[c]02 5",
                                        uid
                                    )
                                )
                            else:
                                numsc = int(numsc1) - 1
            
                                if int(numsc1) < 3 or int(numsc1) > 6:
                                    clients.send(
                                        self.GenResponsMsg(
                                            f"[C][B][FF0000] Usage : /crt <uid> <Squad Type>\n[ffffff]Ví Dụ : \n/ inv 125[c]773[c]683[c]02 4\n/ inv 125[c]773[c]683[c]02 5",
                                            uid
                                        )
                                    )
                                else:
                                    packetmaker = self.skwad_maker()
                                    socket_client.send(packetmaker)
                                    sleep(1)
                                    packetfinal = self.changes(int(numsc))
                                    socket_client.send(packetfinal)
            
                                    invitess = self.invite_skwad(iddd)
                                    socket_client.send(invitess)
                                    iddd1 = parsed_data["5"]["data"]["1"]["data"]
                                    invitessa = self.invite_skwad(iddd1)
                                    socket_client.send(invitessa)
                                    clients.send(
                                        self.GenResponsMsg(
                                            f"Đang Tiến Hành Tạo Nhóm Đội",
                                            uid
                                        )
                                    )
            
                        # التأكد من المغادرة بعد 5 ثوانٍ إذا لم تتم المغادرة تلقائيًا
                        sleep(5)
                        print("=)))")
            
                        leavee = self.leave_s()
                        socket_client.send(leavee)
            
                        # تأخير أطول للتأكد من تنفيذ المغادرة قبل تغيير الوضع
                        sleep(5)
            
                        # إرسال أمر تغيير وضع اللعبة إلى Solo
                        change_to_solo = self.changes(1)  # تأكد أن `1` هو القيمة الصحيحة لـ Solo
                        socket_client.send(change_to_solo)
            
                        # تأخير بسيط قبل إرسال التأكيد للمستخدم
                        sleep(0.1)
            
                        clients.send(
                            self.GenResponsMsg(
                                f"Bot Đã Rời Tổ Đội",
                                uid
                            )
                        )
                except Exception as e:
                    print(f"Error in crt command: {e}")
                    
            if "1200" in data.hex()[0:4] and b"/sp" in data:
                import re
                try:
                    i = re.split("/sp", str(data))[1]
                    sid = str(i).split("(\\x")[0]
            
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data["5"]["data"]["1"]["data"]
            
                    
                    ok, reason = is_user_allowed(uid)
                    if not ok:
                        clients.send(self.GenResponsMsg(f"[C][B][FF0000]❌ {reason}", uid))
                    else:
                        split_data = re.split(rb'/sp', data)
                        room_data = split_data[1].split(b'(')[0].decode().strip().split()
                        if room_data and len(room_data) > 0:
                            player_id = room_data[0]
            
                            if not any(char.isdigit() for char in player_id):
                                clients.send(self.GenResponsMsg(f"[C][B][ff0000] - Error! ", uid))
                            else:
                                player_id = room_data[0]
                                if player_id.isdigit():
                                    if "***" in player_id:
                                        player_id = rrrrrrrrrrrrrr(player_id)
            
                                    packetmaker = self.createpacketinfo(player_id)
                                    socket_client.send(packetmaker)
                                    sleep(0.5)
            
                                    if "IN ROOM" in tempdata:
                                        room_id = get_idroom_by_idplayer(data22)
                                        packetspam = self.spam_room(room_id, player_id)
                                        print(packetspam.hex())
                                        clients.send(
                                            self.GenResponsMsg(
                                                f"Vui Lòng Chờ Đợi", uid
                                            )
                                        )
            
                                        for _ in range(20):
                                            packetspam = self.spam_room(room_id, player_id)
                                            print(" sending spam to " + player_id)
                                            threading.Thread(target=socket_client.send, args=(packetspam,)).start()
            
                                        clients.send(
                                            self.GenResponsMsg(
                                                f"[11EAFD][b][c]Đang Gửi Yêu Cầu join Phòng\n\n [00FF00] - UID: {fix_num(player_id)}\n - Số Lượng: 20\n\n[ffffff]T[c]e[c]le[c]gr[c]a[c]m: [b][c][11EAFD]@cdanhdev", uid
                                            )
                                        )
                                    else:
                                        clients.send(
                                            self.GenResponsMsg(
                                                f"\n\n\n[C][B] [FF00FF]Người Chơi Không Ở Trong Phòngl\n\n\n", uid
                                            )
                                        )
                                else:
                                    clients.send(
                                        self.GenResponsMsg(
                                            f"\n\n\n[C][B] [FF00FF]Vui Lòng Nhập ID Người Chơi!!\n\n\n", uid
                                        )
                                    )
                        else:
                            clients.send(
                                self.GenResponsMsg(
                                    f"\n\n\n[C][B] [FF00FF]Vui Lòng Nhập ID Người Chơi!!!\n\n\n", uid
                                )
                            )
                except Exception as e:
                    print(f"Error in /sp command: {e}")


            if '1200' in data.hex()[0:4] and b'/atk' in data:
                import re
                import time
                try:
                    split_data = re.split(rb'/atk', data)
                    command_parts = split_data[1].split(b'(')[0].decode().strip().split()
            
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data['5']['data']['1']['data']

                    if not command_parts:
                        clients.send(self.GenResponsMsg("[C][B][FF0000]Ô Kìa Bạn Chưa Nhập Teamcode Mà.", uid))
                    else:
                        team_code = command_parts[0]

                        clients.send(
                            self.GenResponsMsg(
                                f"[11EAFD][b][c]Đang Gửi Yêu Cầu S[c]p[c]a[c]m Vô Code\n\n"
                                f"[00FF00] - Team Code: {team_code}\n"
                                f"- Thời Gian: 45s\n", uid
                            )
                        )
            
                        start_packet = self.start_autooo()
                        leave_packet = self.leave_s()
                        duration = 45
            
                        def spam_task():
                            attack_start_time = time.time()
                            while time.time() - attack_start_time < duration:
                                join_teamcode(socket_client, team_code, key, iv)
                                # socket_client.send(start_packet)
                                socket_client.send(leave_packet)
                                time.sleep(0.15)
                            clients.send(self.GenResponsMsg(f"[C][B][00FF00]Đã Hoàn Thành Tới {team_code}!", uid))

                        for _ in range(10):
                            threading.Thread(target=spam_task, daemon=True).start()
            
                except Exception as e:
                    print(f"An error occurred in /attack command: {e}")
                    try:
                        clients.send(self.GenResponsMsg("[C][B][FF0000]Sảy Ra Lỗi Rồi.", uid))
                    except:
                        pass
            
            if "1200" in data.hex()[0:4] and b"/solo" in data:
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]

                # إرسال أمر مغادرة الفريق
                leavee = self.leave_s()
                socket_client.send(leavee)

                sleep(1)  # انتظار للتأكد من تنفيذ الخروج

                # تغيير الوضع إلى Solo
                change_to_solo = self.changes(1)
                socket_client.send(change_to_solo)

                

                clients.send(
                    self.GenResponsMsg(
                        f"[C][B][00FF00]Đã rời đội", uid
                    )
                )

                                          
            if "1200" in data.hex()[0:4] and b"/come" in data:
                try:
                    # تقسيم البيانات القادمة بعد الأمر
                    split_data = re.split(rb'/come', data)
                    command_parts = split_data[1].split(b'(')[0].decode().strip().split()

                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data["5"]["data"]["1"]["data"]

                    # التحقق من وجود كود التيم
                    if not command_parts:
                        clients.send(self.GenResponsMsg("[C][B][FF0000]🔴 Vui lòng nhập mã đội!\n[C][B][FFFF00]Ví dụ: /come ABCD1234", uid))
                        continue

                    team_code = command_parts[0]
                    
                    # إعلام المستخدم ببدء عملية الانضمام
                    clients.send(
                        self.GenResponsMsg(f"[C][B][00FFFF]🤖 Đang tham gia đội...\n[C][B][FFA500]Mã đội: {team_code}", uid)
                    )

                    # محاولة الانضمام للتيم عبر الكود
                    try:
                        join_teamcode(socket_client, team_code, key, iv)
                        
                        # انتظار قصير للتأكد من الانضمام
                        sleep(2)
                        
                        clients.send(
                            self.GenResponsMsg(f"[C][B][00FF00]✅ Đã tham gia đội thành công!\n[C][B][32CD32]Mã đội: {team_code}", uid)
                        )
                        
                    except Exception as join_error:
                        print(f"Error joining team: {join_error}")
                        clients.send(
                            self.GenResponsMsg(f"[C][B][FF0000]❌ Tham gia đội thất bại!\n[C][B][FFFF00]Hãy kiểm tra lại mã đúng: {team_code}", uid)
                        )

                except Exception as e:
                    print(f"Error in /come command: {e}")
                    try:
                        clients.send(self.GenResponsMsg("[C][B][FF0000]❌ Lỗi trong lệnh tham gia", uid))
                    except:
                        pass    
                
            if "1200" in data.hex()[0:4] and b"/start" in data:
                import re
                import time
                try:
                    # تقسيم البيانات القادمة بعد الأمر
                    split_data = re.split(rb'/start', data)
                    command_parts = split_data[1].split(b'(')[0].decode().strip().split()

                    # التأكد من وجود التيم كود على الأقل
                    if not command_parts:
                        clients.send(self.GenResponsMsg("Vui lòng nhập team code.", uid))
                        continue

                    team_code = command_parts[0]
                    spam_count = 2  # إرسال أمر البدء 15 مرة بشكل افتراضي

                    # السماح للمستخدم بتحديد عدد مرات الإرسال
                    if len(command_parts) > 1 and command_parts[1].isdigit():
                        spam_count = int(command_parts[1])
                    
                    # وضع حد أقصى 50 مرة لمنع المشاكل
                    if spam_count > 50:
                        spam_count = 50

                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data['5']['data']['1']['data']

                    clients.send(
                        self.GenResponsMsg(f"[C][B][FFA500]Đang Hiến Hành Join Teamcode...", uid)
                    )

                    # 1. الانضمام إلى الفريق باستخدام الكود
                    join_teamcode(socket_client, team_code, key, iv)
                    time.sleep(2)  # انتظار لمدة ثانيتين للتأكد من الانضمام بنجاح

                    clients.send(
                        self.GenResponsMsg(f"[11EAFD][b][c]Đang Tiến Hành S[c]p[c]a[c]m Bắt Đầu Trận Đấu\n\n [00FF00] - Số Lần Spam Yêu Cầu: {spam_count}", uid)
                    )

                    # 2. إرسال أمر بدء اللعبة بشكل متكرر
                    start_packet = self.start_autooo()
                    for _ in range(spam_count):
                        socket_client.send(start_packet)
                        time.sleep(0) # تأخير بسيط بين كل أمر



                    clients.send(
                        self.GenResponsMsg(f"[C][B][00FF00]Spam Tất Cả Hoàn Thành.", uid)
                    )

                except Exception as e:
                    print(f"An error occurred in /start command: {e}")
                    pass  
            if "1200" in data.hex()[0:4] and b"/ghost" in data:
                try:
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data["5"]["data"]["1"]["data"]
                    
                    # استخراج التيم كود من الأمر
                    command_parts = re.split("/ghost\\s+", str(data))
                    if len(command_parts) < 2:
                        clients.send(
                            self.GenResponsMsg(
                                f"[C][B][FF0000]❌ Vui lòng nhập mã đội!\n"
                                f"[C][B][FFFF00]cách dùng: /ghost [TeamCode]\n"
                                f"[C][B][32CD32]VD: /ghost ABC123", uid
                            )
                        )
                    else:
                        team_code = command_parts[1].split('(')[0].strip()
                        if "***" in team_code:
                            team_code = team_code.replace("***", "106")
                        
                        # رسالة بدء العملية
                        clients.send(
                            self.GenResponsMsg(
                                f"[C][B][9932CC]👻 GHOST MODE ACTIVATED\n"
                                f"[C][B][FF1493]🎯 Mã đội: {team_code}\n"
                                f"[C][B][00FFFF]🔥 Đang tham gia ẩn...", uid
                            )
                        )
                        
                        try:
                            # الانضمام للفريق بالتيم كود
                            join_teamcode(socket_client, team_code, key, iv)
                            
                            # انتظار للتأكد من الانضمام
                            sleep(2)
                            
                            # إرسال رسالة في شات الفريق
                            ghost_message = f"[C][B][FF1493]👻 CDANHDEVLOP VIP 👻\n[C][B][00FFFF]🔥 PREMIUM BOT ACTIVATED 🔥"
                            team_chat_packet = self.send_team_message(ghost_message)
                            socket_client.send(team_chat_packet)
                            
                            # رسالة النجاح
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][00FF00]✅ Đã tham gia ẩn thành công!\n"
                                    f"[C][B][FF1493]👻 CDANHDEVLOP VIP GHOST\n"
                                    f"[C][B][32CD32]🎯 Đội: {team_code}\n"
                                    f"[C][B][FFD700]💎 Bot hiện đang trong đội!", uid
                                )
                            )
                            
                            # إبقاء البوت في الفريق (لا مغادرة تلقائية)
                            print(f"👻 GHOST MODE: Bot đã tham gia đội {team_code} thành công")
                            
                        except Exception as ghost_error:
                            print(f"❌ Lỗi trong Ghost Mode: {ghost_error}")
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][FF0000]❌ Tham gia thất bại!\n"
                                    f"[C][B][FFFF00]Hãy kiểm tra lại: {team_code}\n"
                                    f"[C][B][FFA500]💡 Đảm bảo rằng teamcode tồn tại", uid
                                )
                            )
                            
                except Exception as e:
                    print(f"❌ lỗi trong /ghost: {e}")
                    try:
                        clients.send(
                            self.GenResponsMsg(
                                f"[C][B][FF0000]❌ Đã xãy ra lỗi Ghost Mode\n"
                                f"[C][B][FFFF00]Hãy thử lại", uid
                            )
                        )
                    except:
                        pass                         
                      
            if "1200" in data.hex()[0:4] and b"/addVOPN" in data:
                i = re.split("/addVOPN", str(data))[1]
                if "***" in i:
                    i = i.replace("***", "106")
                sid = str(i).split("(\\x")[0]
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                split_data = re.split(rb'/add', data)
                room_data = split_data[1].split(b'(')[0].decode().strip().split()
                if room_data:
                    print(room_data)
                    iddd = room_data[0]
                    numsc1 = room_data[1] if len(room_data) > 1 else None

                    if numsc1 is None:
                        clients.send(
                            self.GenResponsMsg(
                                f"[C][B] [FF00FF]Please write id and count of the group\n[ffffff]Example : \n/ add 123[c]456[c]78 4\n/ add 123[c]456[c]78 5", uid
                            )
                        )
                    else:
                        numsc = int(numsc1) - 1
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        if int(numsc1) < 3 or int(numsc1) > 6:
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][FF0000] Usage : /add <uid> <Squad Type>\n[ffffff]Example : \n/ add 12345678 4\n/ add 12345678 5", uid
                                )
                            )
                        else:
                            packetmaker = self.skwad_maker()
                            socket_client.send(packetmaker)
                            sleep(1)
                            packetfinal = self.changes(int(numsc))
                            socket_client.send(packetfinal)
                            
                            invitess = self.invite_skwad(iddd)
                            socket_client.send(invitess)
                            iddd1 = parsed_data["5"]["data"]["1"]["data"]
                            invitessa = self.invite_skwad(iddd1)
                            socket_client.send(invitessa)
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][00ff00]- AcCept The Invite QuickLy ! ", uid
                                )
                            )
                            leaveee1 = True
                            while leaveee1:
                                if leaveee == True:
                                    print("Leave")
                                    leavee = self.leave_s()
                                    sleep(5)
                                    socket_client.send(leavee)   
                                    leaveee = False
                                    leaveee1 = False
                                    clients.send(
                                        self.GenResponsMsg(
                                            f"[C][B] [FF00FF]succes !", uid
                                        )
                                    )    
                                if pleaseaccept == True:
                                    print("Leave")
                                    leavee = self.leave_s()
                                    socket_client.send(leavee)   
                                    leaveee1 = False
                                    pleaseaccept = False
                                    clients.send(
                                        self.GenResponsMsg(
                                            f"[C][B] [FF00FF]Please accept the invite", uid
                                        )
                                    )   
                else:
                    clients.send(
                        self.GenResponsMsg(
                            f"[C][B] [FF00FF]Please write id and count of the group\n[ffffff]Example : \n/ inv 123[c]456[c]78 4\n/ inv 123[c]456[c]78 5", uid
                        )
                    ) 

	                    
                    
    def parse_my_message(self, serialized_data):
        MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
        MajorLogRes.ParseFromString(serialized_data)
        
        timestamp = MajorLogRes.kts
        key = MajorLogRes.ak
        iv = MajorLogRes.aiv
        BASE64_TOKEN = MajorLogRes.token
        timestamp_obj = Timestamp()
        timestamp_obj.FromNanoseconds(timestamp)
        timestamp_seconds = timestamp_obj.seconds
        timestamp_nanos = timestamp_obj.nanos
        combined_timestamp = timestamp_seconds * 1_000_000_000 + timestamp_nanos
        return combined_timestamp, key, iv, BASE64_TOKEN

    def GET_PAYLOAD_BY_DATA(self,JWT_TOKEN , NEW_ACCESS_TOKEN,date):
        token_payload_base64 = JWT_TOKEN.split('.')[1]
        token_payload_base64 += '=' * ((4 - len(token_payload_base64) % 4) % 4)
        decoded_payload = base64.urlsafe_b64decode(token_payload_base64).decode('utf-8')
        decoded_payload = json.loads(decoded_payload)
        NEW_EXTERNAL_ID = decoded_payload['external_id']
        SIGNATURE_MD5 = decoded_payload['signature_md5']
        now = datetime.now()
        now =str(now)[:len(str(now))-7]
        formatted_time = date
        payload = bytes.fromhex("1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3131342e32422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033")
        payload = payload.replace(b"2025-07-30 11:02:51", str(now).encode())
        payload = payload.replace(b"ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a", NEW_ACCESS_TOKEN.encode("UTF-8"))
        payload = payload.replace(b"996a629dbcdb3964be6b6978f5d814db", NEW_EXTERNAL_ID.encode("UTF-8"))
        payload = payload.replace(b"7428b253defc164018c604a1ebbfebdf", SIGNATURE_MD5.encode("UTF-8"))
        PAYLOAD = payload.hex()
        PAYLOAD = encrypt_api(PAYLOAD)
        PAYLOAD = bytes.fromhex(PAYLOAD)
        whisper_ip, whisper_port, online_ip, online_port = self.GET_LOGIN_DATA(JWT_TOKEN , PAYLOAD)
        return whisper_ip, whisper_port, online_ip, online_port
    
    def dec_to_hex(ask):
        ask_result = hex(ask)
        final_result = str(ask_result)[2:]
        if len(final_result) == 1:
            final_result = "0" + final_result
            return final_result
        else:
            return final_result
    def convert_to_hex(PAYLOAD):
        hex_payload = ''.join([f'{byte:02x}' for byte in PAYLOAD])
        return hex_payload
    def convert_to_bytes(PAYLOAD):
        payload = bytes.fromhex(PAYLOAD)
        return payload
    def GET_LOGIN_DATA(self, JWT_TOKEN, PAYLOAD):
        url = "https://clientbp.common.ggbluefox.com/GetLoginData"
        headers = {
            'Expect': '100-continue',
            'Authorization': f'Bearer {JWT_TOKEN}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB50',
            'Content-Type': 'application0-www-form-urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
            'Host': 'clientbp.common.ggbluefox.com',
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate, br',
        }
        
        max_retries = 3
        attempt = 0

        while attempt < max_retries:
            try:
                response = requests.post(url, headers=headers, data=PAYLOAD,verify=False)
                response.raise_for_status()
                x = response.content.hex()
                json_result = get_available_room(x)
                parsed_data = json.loads(json_result)
                print(parsed_data)
                
                whisper_address = parsed_data['32']['data']
                online_address = parsed_data['14']['data']
                online_ip = online_address[:len(online_address) - 6]
                whisper_ip = whisper_address[:len(whisper_address) - 6]
                online_port = int(online_address[len(online_address) - 5:])
                whisper_port = int(whisper_address[len(whisper_address) - 5:])
                return whisper_ip, whisper_port, online_ip, online_port
            
            except requests.RequestException as e:
                print(f"Request failed: {e}. Attempt {attempt + 1} of {max_retries}. Retrying...")
                attempt += 1
                time.sleep(2)

        print("Failed to get login data after multiple attempts.")
        return None, None

    def guest_token(self,uid , password):
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {"Host": "100067.connect.garena.com","User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 10;en;EN;)","Content-Type": "application/x-www-form-urlencoded","Accept-Encoding": "gzip, deflate, br","Connection": "close",}
        data = {"uid": f"{uid}","password": f"{password}","response_type": "token","client_type": "2","client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3","client_id": "100067",}
        response = requests.post(url, headers=headers, data=data)
        data = response.json()
        NEW_ACCESS_TOKEN = data['access_token']
        NEW_OPEN_ID = data['open_id']
        OLD_ACCESS_TOKEN = "ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a"
        OLD_OPEN_ID = "996a629dbcdb3964be6b6978f5d814db"
        time.sleep(0.2)
        data = self.TOKEN_MAKER(OLD_ACCESS_TOKEN , NEW_ACCESS_TOKEN , OLD_OPEN_ID , NEW_OPEN_ID,uid)
        return(data)
        
    def TOKEN_MAKER(self,OLD_ACCESS_TOKEN , NEW_ACCESS_TOKEN , OLD_OPEN_ID , NEW_OPEN_ID,id):
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB50',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Content-Length': '928',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.common.ggbluefox.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        data = bytes.fromhex('1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3131342e32422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033')
        data = data.replace(OLD_OPEN_ID.encode(),NEW_OPEN_ID.encode())
        data = data.replace(OLD_ACCESS_TOKEN.encode() , NEW_ACCESS_TOKEN.encode())
        hex = data.hex()
        d = encrypt_api(data.hex())
        Final_Payload = bytes.fromhex(d)
        URL = "https://loginbp.ggblueshark.com/MajorLogin"

        RESPONSE = requests.post(URL, headers=headers, data=Final_Payload,verify=False)
        
        combined_timestamp, key, iv, BASE64_TOKEN = self.parse_my_message(RESPONSE.content)
        if RESPONSE.status_code == 200:
            if len(RESPONSE.text) < 10:
                return False
            whisper_ip, whisper_port, online_ip, online_port =self.GET_PAYLOAD_BY_DATA(BASE64_TOKEN,NEW_ACCESS_TOKEN,1)
            self.key = key
            self.iv = iv
            print(key, iv)
            return(BASE64_TOKEN, key, iv, combined_timestamp, whisper_ip, whisper_port, online_ip, online_port)
        else:
            return False
    
    def time_to_seconds(hours, minutes, seconds):
        return (hours * 3600) + (minutes * 60) + seconds

    def seconds_to_hex(seconds):
        return format(seconds, '04x')
    
    def extract_time_from_timestamp(timestamp):
        dt = datetime.fromtimestamp(timestamp)
        h = dt.hour
        m = dt.minute
        s = dt.second
        return h, m, s
    
    def get_tok(self):
        global g_token
        token, key, iv, Timestamp, whisper_ip, whisper_port, online_ip, online_port = self.guest_token(self.id, self.password)
        g_token = token
        print(whisper_ip, whisper_port)
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            account_id = decoded.get('account_id')
            encoded_acc = hex(account_id)[2:]
            hex_value = dec_to_hex(Timestamp)
            time_hex = hex_value
            BASE64_TOKEN_ = token.encode().hex()
            print(f"Token decoded and processed. Account ID: {account_id}")
        except Exception as e:
            print(f"Error processing token: {e}")
            return

        try:
            head = hex(len(encrypt_packet(BASE64_TOKEN_, key, iv)) // 2)[2:]
            length = len(encoded_acc)
            zeros = '00000000'

            if length == 9:
                zeros = '0000000'
            elif length == 8:
                zeros = '00000000'
            elif length == 10:
                zeros = '000000'
            elif length == 7:
                zeros = '000000000'
            else:
                print('Unexpected length encountered')
            head = f'0115{zeros}{encoded_acc}{time_hex}00000{head}'
            final_token = head + encrypt_packet(BASE64_TOKEN_, key, iv)
            print("Final token constructed successfully.")
        except Exception as e:
            print(f"Error constructing final token: {e}")
        token = final_token
        self.connect(token, 'anything', key, iv, whisper_ip, whisper_port, online_ip, online_port)
        
      
        return token, key, iv
        
with open('accs.txt', 'r') as file:
    data = json.load(file)
ids_passwords = list(data.items())
def run_client(id, password):
    print(f"ID: {id}, Password: {password}")
    client = FF_CLIENT(id, password)
    client.start()
    
max_range = 300000
num_clients = len(ids_passwords)
num_threads = 1
start = 0
end = max_range
step = (end - start) // num_threads
threads = []
for i in range(num_threads):
    ids_for_thread = ids_passwords[i % num_clients]
    id, password = ids_for_thread
    thread = threading.Thread(target=run_client, args=(id, password))
    threads.append(thread)
    time.sleep(3)
    thread.start()

for thread in threads:
    thread.join()
    
if __name__ == "__main__":
    try:
        client_thread = FF_CLIENT(id="4081109750", password="2D261943A3D128D0CCC75A5F7B33E3EE49A6F0B2E34C78978B39E356E6F94E34")
        client_thread.start()
    except Exception as e:
        logging.error(f"Error occurred: {e}")
        restart_program()

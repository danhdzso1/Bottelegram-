import threading
import jwt
import random
import json
import requests
import google.protobuf
import datetime
from datetime import datetime
import base64
import logging
import re
import socket
import os
import binascii
import sys
import psutil
import time
from freefireimport import *
from time import sleep
from google.protobuf.timestamp_pb2 import Timestamp
from google.protobuf.json_format import MessageToJson
from protobuf_decoder.protobuf_decoder import Parser
from threading import Thread
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import httpx
import urllib3
import MajorLg
import taotoken

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
paylod_token1 = "3a07312e3131312e32aa01026172b201203535656437353966636639346638353831336535376232656338343932663563ba010134ea0140366662376664656638363538666430333137346564353531653832623731623231646238313837666130363132633865616631623633616136383766316561659a060134a2060134ca03203734323862323533646566633136343031386336303461316562626665626466"
freefire_version = "ob50"
client_secret = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
chat_ip = "103.108.103.30"
chat_port = 39699
key2 = "projects_xxx_3ei93k_codex_xdfox"

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

def rrrrrrrrrrrrrr(number):
    if isinstance(number, str) and '***' in number:
        return number.replace('***', '106')
    return number

def Encrypt(number):
    try:
        number = int(number)
        encoded_bytes = []
        while True:
            byte = number & 0x7F
            number >>= 7
            if number:
                byte |= 0x80
            encoded_bytes.append(byte)
            if not number:
                break
        return bytes(encoded_bytes).hex()
    except Exception as e:
        logging.error(f"Error in Encrypt: {e}")
        sys.exit(1)

def generate_random_word():
    word_list = [
        "TmrVirus080", "TmrVirus", "VirusTeam", "VsTeam", "TmrMod", "Tmr080", "CdanhzZz", "TmrVip777"
    ]
    return random.choice(word_list)

def generate_random_color():
    color_list = [
        "[00FF00][b][c]", "[FFDD00][b][c]", "[3813F3][b][c]", "[FF0000][b][c]", "[0000FF][b][c]",
        "[FFA500][b][c]", "[DF07F8][b][c]", "[11EAFD][b][c]", "[DCE775][b][c]", "[A8E6CF][b][c]",
        "[7CB342][b][c]", "[FF0000][b][c]", "[FFB300][b][c]", "[90EE90][b][c]", "[FF4500][b][c]",
        "[FFD700][b][c]", "[32CD32][b][c]", "[87CEEB][b][c]", "[9370DB][b][c]", "[FF69B4][b][c]",
        "[8A2BE2][b][c]", "[00BFFF][b][c]", "[1E90FF][b][c]", "[20B2AA][b][c]", "[00FA9A][b][c]",
        "[008000][b][c]", "[FFFF00][b][c]", "[FF8C00][b][c]", "[DC143C][b][c]", "[FF6347][b][c]",
        "[FFA07A][b][c]", "[FFDAB9][b][c]", "[CD853F][b][c]", "[D2691E][b][c]", "[BC8F8F][b][c]",
        "[F0E68C][b][c]", "[556B2F][b][c]", "[808000][b][c]", "[4682B4][b][c]", "[6A5ACD][b][c]",
        "[7B68EE][b][c]", "[8B4513][b][c]", "[C71585][b][c]", "[4B0082][b][c]", "[B22222][b][c]",
        "[228B22][b][c]", "[8B008B][b][c]", "[483D8B][b][c]", "[556B2F][b][c]", "[800000][b][c]",
        "[008080][b][c]", "[000080][b][c]", "[800080][b][c]", "[808080][b][c]", "[A9A9A9][b][c]",
        "[D3D3D3][b][c]", "[F0F0F0][b][c]"
    ]
    return random.choice(color_list)

def get_random_avatar():
    avatar_list = [
        '902000061', '902000060', '902000064', '902000065', '902000066',
        '902000074', '902000075', '902000077', '902000078', '902000084',
        '902000085', '902000087', '902000091', '902000094', '902000306',
        '902000091', '902000208', '902000209', '902000210', '902000211',
        '902047016', '902047016', '902000347', '902049014', '902049016',
        '902042013', '902038024', '902042010', '902027027', '902042011',
        '902000017', '902000244', '902036017', '902045006', '902000141',
        '902000157'
    ]
    return random.choice(avatar_list)

def get_jwt_token():
    global jwt_token
    url = "https://projects-fox-x-get-jwt.vercel.app/get?uid=4081109750&password=2D261943A3D128D0CCC75A5F7B33E3EE49A6F0B2E34C78978B39E356E6F94E34"
    try:
        response = httpx.get(url)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                jwt_token = data['token']
                if os.path.exists("token.txt"):
                    os.remove("token.txt")
                with open("token.txt", "w") as f:
                    f.write(jwt_token)
            else:
                logging.error("get lại token đi bro")
        else:
            logging.error(f"thất bại get lại đi")
    except httpx.RequestError as e:
        logging.error(e)

def token_updater():
    while True:
        get_jwt_token()
        time.sleep(8 * 3600)

token_thread = Thread(target=token_updater, daemon=True)
token_thread.start()

class FF_CLIENT(threading.Thread):
    def __init__(self, id, password, target_uid):
        super().__init__()
        self.id = id
        self.password = password
        self.target_uid = target_uid
        self.key = None
        self.iv = None
        self.get_tok()

    def parse_my_message(self, serialized_data):
        try:
            MajorLogRes = MajorLg.MajorLoginRes()
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
            self.key = key
            self.iv = iv
            return combined_timestamp, key, iv, BASE64_TOKEN
        except Exception as e:
            logging.error(e)
            return None, None, None, None

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
            logging.error(e)

    def invite_skwad(self, idplayer):
        fields = {
            1: 2,
            2: {
                1: int(idplayer),
                10: int(get_random_avatar()),
                2: "VN",
                4: 1
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, self.key, self.iv)) // 2
        header_lenth_final = self.dec_to_hex(header_lenth)
        prefix = "051500" + "0" * (6 - len(header_lenth_final))
        final_packet = prefix + header_lenth_final + self.nmnmmmmn(packet)
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
                    8: "1.111.5",
                    9: 3,
                    10: 2
                }
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, self.key, self.iv)) // 2
        header_lenth_final = self.dec_to_hex(header_lenth)
        prefix = "051500" + "0" * (6 - len(header_lenth_final))
        final_packet = prefix + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def changes(self, num):
        fields = {
            1: 17,
            2: {
                1: 12263472229,
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
        header_lenth = len(encrypt_packet(packet, self.key, self.iv)) // 2
        header_lenth_final = self.dec_to_hex(header_lenth)
        prefix = "051500" + "0" * (6 - len(header_lenth_final))
        final_packet = prefix + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def leave_s(self):
        fields = {
            1: 7,
            2: {
                1: 12263472229
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, self.key, self.iv)) // 2
        header_lenth_final = self.dec_to_hex(header_lenth)
        prefix = "051500" + "0" * (6 - len(header_lenth_final))
        final_packet = prefix + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def GenResponsMsg(self, Msg, Enc_Id):
        fields = {
            1: 1,
            2: {
                1: 12263472229,
                2: Enc_Id,
                3: 2,
                4: str(Msg),
                5: int(datetime.now().timestamp()),
                7: 2,
                9: {
                    1: "VirusTeam080",
                    2: int(get_random_avatar()),
                    4: 330,
                    8: "VirusTeam080",
                    10: 1,
                    11: 1
                },
                10: "en",
                13: {
                    2: 1,
                    3: 1
                },
                14: ""
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, self.key, self.iv)) // 2
        header_lenth_final = self.dec_to_hex(header_lenth)
        prefix = "121500" + "0" * (6 - len(header_lenth_final))
        final_packet = prefix + header_lenth_final + self.nmnmmmmn(packet)
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
                    4: "wW_T",
                    6: 11,
                    8: "1.111.5",
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
        header_lenth = len(encrypt_packet(packet, self.key, self.iv)) // 2
        header_lenth_final = self.dec_to_hex(header_lenth)
        prefix = "051500" + "0" * (6 - len(header_lenth_final))
        final_packet = prefix + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
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
            8: "1.111.5",
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
        prefix = "051500" + "0" * (6 - len(header_lenth_final))
        final_packet = prefix + header_lenth_final +  self.nmnmmmmn(packet)    
        return bytes.fromhex(final_packet)
    def start_autooo(self):
        fields = {
            1: 9,
            2: {
                1: 12263472229
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, self.key, self.iv)) // 2
        header_lenth_final = self.dec_to_hex(header_lenth)
        prefix = "051500" + "0" * (6 - len(header_lenth_final))
        final_packet = prefix + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def sockf1(self, tok, host, port, packet, key, iv):
        global socket_client
        global sent_inv
        global tempid
        global start_par
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
        port = int(port)
        socket_client.connect((host, port))
        socket_client.send(bytes.fromhex(tok))
        guiyeucau = self.request_skwad(self.target_uid)
        socket_client.send(guiyeucau)
        for _ in range(150):
            socket_client.send(guiyeucau)
        sleep(5)
        for _ in range(150):
            socket_client.send(guiyeucau)
        sleep(7)
        for _ in range(150):
            socket_client.send(guiyeucau)
        uid = fix_num(self.target_uid)
        
        leavee = self.leave_s()
        socket_client.send(leavee)
    def connect(self, tok, host, port, packet, key, iv):
        global clients
        clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = int(port)
        try:
            clients.connect((host, port))
            clients.send(bytes.fromhex(tok))
            thread = threading.Thread(
                target=self.sockf1, args=(tok, chat_ip, chat_port, "anything", key, iv)
            )
            thread.start()
            thread.join()
        except socket.error as e:
            logging.error(f"Socket error in connect: {e}")
        finally:
            try:
                clients.close()
            except:
                pass

    def dec_to_hex(self, ask):
        ask_result = hex(ask)
        final_result = str(ask_result)[2:]
        if len(final_result) == 1:
            final_result = "0" + final_result
        return final_result

    def GET_PAYLOAD_BY_DATA(self, JWT_TOKEN, NEW_ACCESS_TOKEN, date):
        try:
            token_payload_base64 = JWT_TOKEN.split('.')[1]
            token_payload_base64 += '=' * ((4 - len(token_payload_base64) % 4) % 4)
            decoded_payload = base64.urlsafe_b64decode(token_payload_base64).decode('utf-8')
            decoded_payload = json.loads(decoded_payload)
            NEW_EXTERNAL_ID = decoded_payload['external_id']
            SIGNATURE_MD5 = decoded_payload['signature_md5']
            now = datetime.now()
            now = str(now)[:len(str(now))-7]
            payload = bytes.fromhex(paylod_token1)
            payload = payload.replace(b"2024-12-26 13:02:43", str(now).encode())
            payload = payload.replace(b"88332848f415ca9ca98312edcd5fe8bc6547bc6d0477010a7feaf97e3435aa7f", NEW_ACCESS_TOKEN.encode("UTF-8"))
            payload = payload.replace(b"e1ccc10e70d823f950f9f4c337d7d20a", NEW_EXTERNAL_ID.encode("UTF-8"))
            payload = payload.replace(b"7428b253defc164018c604a1ebbfeMEf", SIGNATURE_MD5.encode("UTF-8"))
            PAYLOAD = payload.hex()
            PAYLOAD = encrypt_api(PAYLOAD)
            PAYLOAD = bytes.fromhex(PAYLOAD)
            ip, port = self.GET_LOGIN_DATA(JWT_TOKEN, PAYLOAD)
            return ip, port
        except Exception as e:
            logging.error(f"Error in GET_PAYLOAD_BY_DATA: {e}")
            return None, None

    def GET_LOGIN_DATA(self, JWT_TOKEN, PAYLOAD):
        url = "https://clientbp.common.ggbluefox.com/GetLoginData"
        headers = {
            'Expect': '100-continue',
            'Authorization': f'Bearer {JWT_TOKEN}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': freefire_version,
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
            'Host': 'clientbp.common.ggbluefox.com',
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate, br',
        }
        max_retries = 3
        attempt = 0
        while attempt < max_retries:
            try:
                response = requests.post(url, headers=headers, data=PAYLOAD, verify=False)
                response.raise_for_status()
                x = response.content.hex()
                json_result = get_available_room(x)
                parsed_data = json.loads(json_result)
                address = parsed_data['32']['data']
                ip = address[:len(address) - 6]
                port = address[len(address) - 5:]
                return ip, port
            except requests.RequestException as e:
                logging.error(f"Request error in GET_LOGIN_DATA, attempt {attempt + 1}: {e}")
                attempt += 1
                time.sleep(2)
        return None, None

    def guest_token(self, uid, password):
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close",
        }
        data = {
            "uid": f"{uid}",
            "password": f"{password}",
            "response_type": "token",
            "client_type": "2",
            "client_secret": client_secret,
            "client_id": "100067",
        }
        try:
            response = requests.post(url, headers=headers, data=data)
            data = response.json()
            NEW_ACCESS_TOKEN = data['access_token']
            NEW_OPEN_ID = data['open_id']
            OLD_ACCESS_TOKEN = "6fb7fdef8658fd03174ed551e82b71b21db8187fa0612c8eaf1b63aa687f1eae"
            OLD_OPEN_ID = "55ed759fcf94f85813e57b2ec8492f5c"
            time.sleep(0.2)
            data = self.TOKEN_MAKER(OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, uid)
            return data
        except Exception as e:
            return False

    def TOKEN_MAKER(self, OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, id):
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
        try:
            data = bytes.fromhex(paylod_token1)
            data = data.replace(OLD_OPEN_ID.encode(), NEW_OPEN_ID.encode())
            data = data.replace(OLD_ACCESS_TOKEN.encode(), NEW_ACCESS_TOKEN.encode())
            hex = data.hex()
            d = encrypt_api(data.hex())
            Final_Payload = bytes.fromhex(d)
            URL = "https://loginbp.ggblueshark.com/MajorLogin"
            RESPONSE = requests.post(URL, headers=headers, data=Final_Payload, verify=False)
            combined_timestamp, key, iv, BASE64_TOKEN = self.parse_my_message(RESPONSE.content)
            if RESPONSE.status_code == 200:
                if len(RESPONSE.text) < 10:
                    return False
                ip, port = self.GET_PAYLOAD_BY_DATA(BASE64_TOKEN, NEW_ACCESS_TOKEN, 1)
                self.key = key
                self.iv = iv
                return (BASE64_TOKEN, key, iv, combined_timestamp, ip, port)
            else:
                return False
        except Exception as e:
            return False

    def get_tok(self):
        global g_token
        token, key, iv, Timestamp, ip, port = self.guest_token(self.id, self.password)
        g_token = token
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            account_id = decoded.get('account_id')
            encoded_acc = hex(account_id)[2:]
            hex_value = self.dec_to_hex(Timestamp)
            time_hex = hex_value
            BASE64_TOKEN_ = token.encode().hex()
        except Exception as e:
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
            head = f'0115{zeros}{encoded_acc}{time_hex}00000{head}'
            final_token = head + encrypt_packet(BASE64_TOKEN_, key, iv)
        except Exception as e:
            logging.error(e)
        token = final_token
        self.connect(token, ip, port, 'anything', key, iv)
        
        return token, key, iv

def encrypt_api(plain_text):
    try:
        plain_text = bytes.fromhex(plain_text)
        key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
        iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
        return cipher_text.hex()
    except Exception as e:
        logging.error(e)
        return None

def get_available_room(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_objects = parsed_results
        parsed_results_dict = parse_results(parsed_results_objects)
        json_data = json.dumps(parsed_results_dict)
        return json_data
    except Exception as e:
        logging.error(e)
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

def restart_program():
    try:
        p = psutil.Process(os.getpid())
        for handler in p.open_files():
            if handler.fd in (0, 1, 2):
                continue
            try:
                os.close(handler.fd)
            except Exception as e:
                logging.error(e)
        python = sys.executable
        os.execl(python, python, *sys.argv)
    except Exception as e:
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("python test.py uid-cần-spam-đội")
        sys.exit(1)
    try:
        target_uid = int(sys.argv[1])
        logging.info(f"Đang Spam Đội {target_uid}...")
    except ValueError:
        sys.exit(1)
    try:
        client_thread = FF_CLIENT(
            id="4081109750",
            password="2D261943A3D128D0CCC75A5F7B33E3EE49A6F0B2E34C78978B39E356E6F94E34",
            target_uid=target_uid
        )
        client_thread.start()
        client_thread.join()
    except Exception as e:
        restart_program()
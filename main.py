import threading
import jwt
import random
from threading import Thread
import json
import requests
import google.protobuf
from protobuf_decoder.protobuf_decoder import Parser
import json

import datetime
from datetime import datetime
from google.protobuf.json_format import MessageToJson
import my_message_pb2
import data_pb2
import base64
import logging
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
from important_zitado import*
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
    "[FFDD00][b][c]",
    "[3813F3][b][c]",
    "[FF0000][b][c]",
    "[FFA500][b][c]",
    "[DF07F8][b][c]",
    "[11EAFD][b][c]",
    "[DCE775][b][c]",
    "[A8E6CF][b][c]",
    "[7CB342][b][c]",
    "[FF0000][b][c]",
    "[FFB300][b][c]",
    "[90EE90][b][c]"
]
	random_color = random.choice(color_list)
	return  random_color

def fix_num(num):
    fixed = ""
    count = 0
    num_str = str(num)  # Convert the number to a string

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
        
        



		
def Encrypt(number):
    number = int(number)  # تحويل الرقم إلى عدد صحيح
    encoded_bytes = []    # إنشاء قائمة لتخزين البايتات المشفرة

    while True:  # حلقة تستمر حتى يتم تشفير الرقم بالكامل
        byte = number & 0x7F  # استخراج أقل 7 بتات من الرقم
        number >>= 7  # تحريك الرقم لليمين بمقدار 7 بتات
        if number:
            byte |= 0x80  # تعيين البت الثامن إلى 1 إذا كان الرقم لا يزال يحتوي على بتات إضافية

        encoded_bytes.append(byte)
        if not number:
            break  # التوقف إذا لم يتبقى بتات إضافية في الرقم

    return bytes(encoded_bytes).hex()

def send_spam(uid):
    url = f"http://160.250.137.144:5004/addfriend?uid={uid}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if "message" in data:  # تحقق من وجود الرسالة في الاستجابة
                return f" {data['message']}"
            else:
                return f"Spam sent to {uid} successfully !"
        else:
            return f" - An ErrOr OccUrrRd, STatuS CoDe > {response.status_code}"
    except Exception as e:
        return f"- An error occurred > {e}"
        


#################################



	
def likes_plus(uid, region="ME"):
    url = f"https://like-freefireobi.vercel.app/like?uid={uid}&server_name=vn&key=obibot1102"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return f"""{generate_random_color()}-----------------------------------\n\n- PlaYer > {data.get('player', 'ErRor')}
- Level > {data.get('level', 'ErRor')}
- LikEs Beforr > {data.get('likes_before', 0)}
- LikEs After > {data.get('likes_after', 0)}
- LikEs Added > {data.get('likes_added', 0)}\n\n-----------------------------------"""
        else:
            return f"{generate_random_color()}-----------------------------------\n\n- An ErrOr OccUrrRd, STatuS CoDe > {response.status_code}\n\n-----------------------------------"
    except Exception as e:
        return f"{generate_random_color()}-----------------------------------\n\n- An error occurred > {e}\n\n-----------------------------------"



def get_random_avatar():
	avatar_list = ['902000061','902000060','902000064','902000065','902000066','902000066','902000074','902000075','902000077','902000078','902000084','902000085','902000087','902000091','902000094','902000306']
	random_avatar = random.choice(avatar_list)
	return  random_avatar






class FF_CLIENT(threading.Thread):
    def __init__(self, id, password):
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        self.get_tok()
        
    def keep_alive(self):
        while True:
            try:
                if hasattr(self, 'clients') and self.clients:
                    self.clients.sendall(b'\x00\x00\x00\x00')  # إرسال "ping"
                else:
                    print("⚠️ الاتصال غير موجود، إنهاء keep_alive.")
                break  # الخروج من الحلقة إذا لم يكن هناك اتصال
            except (BrokenPipeError, ConnectionResetError):
                print("🚨 الاتصال انقطع أثناء إرسال ping، سيتم إعادة الاتصال...")
                self.reconnect()  # إعادة الاتصال تلقائيًا
                break  # إنهاء الحلقة بعد محاولة إعادة الاتصال
            except Exception as e:
                print(f"⚠️ خطأ غير متوقع أثناء keep_alive: {e}")
                break  # إنهاء الحلقة في حالة وجود خطأ غير متوقع

        time.sleep(10)  # انتظار 5 دقائق قبل إرسال الحزمة التالية  # خروج من الحلقة إذا حدث خطأ
                    
    def connect(self, tok, host, port, packet, key, iv):
        global clients
        clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = int(port)
        clients.connect((host, port))
        clients.send(bytes.fromhex(tok))

        while True:
            data = clients.recv(9999)
            
            if data == b"":
                print("🚨 الاتصال مغلق، جارٍ إعادة الاتصال...")
            restart_connection()
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
    connections = psutil.net_connections()
    for handler in open_files:
        try:
            os.close(handler.fd)
        except Exception:
            pass
            
    for conn in connections:
        try:
            conn.close()
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

    def spam_room(self, idroom, idplayer, custom_name):
        fields = {
        1: 78,
        2: {
            1: int(idroom),
            2: f"{generate_random_color()}{custom_name}",  # استخدام الاسم الذي يدخله المستخدم
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
                2: "ME",
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
            1: 11675673818
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
            2: "ME",
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
    def request_skwad(self, idplayer):
        fields = {
        1: 33,
        2: {
            1: int(idplayer),
            2: "ME",
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
            1: 11675673818,
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
            1: 11675673818
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
            1: 11675673818
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
        #print(Besto_Packet)
        
        
    def joinclanchat(self):
        fields = {
            1: 3,
            2: {
            1: int(3074997584),
            2: 1,
            4: str("Vhz6NTOFiOaAFSRoA+s4nA")
            }
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
            3: 901041021,
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
            4: "wW_T",
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

    def sockf1(self, tok, host, port, packet, key, iv):
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
        port = int(port)

        socket_client.connect((host,port))
        print(f" Con port {port} Host {host} ")
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
                        tempdata = f"{tempdata}"
                    else:
                        idplayer = parsed_data["5"]["data"]["1"]["data"]["1"]["data"]
                        idplayer1 = fix_num(idplayer)
                        if tempdata == "IN ROOM":
                            idrooom = get_idroom_by_idplayer(packett)
                            idrooom1 = fix_num(idrooom)
                            
                            tempdata = f"{generate_random_color()}-----------------------------------\n\n- id : {idplayer1}\n\n- status : {tempdata}\n\n- id room : {idrooom1}\n\n-----------------------------------"
                            data22 = packett
                            print(data22)
                            
                        if "INSQUAD" in tempdata:
                            idleader = get_leader(packett)
                            idleader1 = fix_num(idleader)
                            tempdata = f"{generate_random_color()}-----------------------------------\n\n- id : {idplayer1}\n\n- status : {tempdata}\n\n- leader id : {idleader1}\n\n-----------------------------------"
                        else:
                            tempdata = f"{generate_random_color()}-----------------------------------\n\n- id : {idplayer1}\n\n- status : {tempdata}\n\n-----------------------------------"
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
                    tempdata1 = f"{tempdata}\n- Room name : {nameroom}\n- Max player : {maxplayer1}\n- Live player : {nowplayer1}"
                    print(tempdata1)
                    

                    
                
                    
            if data2 == b"":
                
                print("Connection closed by remote host")
                restart_program()
                break
    
    
    def connect(self, tok, host, port, packet, key, iv):
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
        port = int(port)
        clients.connect((host, port))
        clients.send(bytes.fromhex(tok))
        thread = threading.Thread(
            target=self.sockf1, args=(tok, "103.108.103.31", 39699, "anything", key, iv)
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
[b][c][FF0000]-----------------------------------

[C][B][ffffff]- Xin Cho! Ti C Th Gip G Cho Bn?
[C][B][ffffff]-  Bit Tt C Lnh Vui Lng Ghi :

[ffffff]-  [ /help ]           


[C][B][ffffff]- TRANBAODEV


[b][c][FF0000]-----------------------------------
[C][B][ffffff]- Tiktok : tranbaodev
[C][B][ffffff]-  t l g rm: @tranbaodev
[b][c][FF0000]-----------------------------------""", idinv
                        )
                )
                senthi = False

            

#################################

            
            
            if "1200" in data.hex()[0:4]:
               
                json_result = get_available_room(data.hex()[10:])
                print(data.hex())
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]
                if "8" in parsed_data["5"]["data"] and "data" in parsed_data["5"]["data"]["8"]:
                    uexmojiii = parsed_data["5"]["data"]["8"]["data"]
                    if uexmojiii == "DefaultMessageWithKey":
                        pass
                    else:
                        clients.send(
                            self.GenResponsMsg(
                                f"""
[b][c][FF0000]-----------------------------------

[[C][B][ffffff]- Xin Cho! Ti C Th Gip G Cho Bn?
[C][B][ffffff]-  Bit Tt C Lnh Vui Lng Ghi :

[ffffff]-  [ /help ]           


[C][B][ffffff]- TRANBAODEV


[b][c][FF0000]-----------------------------------
[C][B][ffffff]- Tiktok : tranbaodev
[C][B][ffffff]-  t l g rm: @tranbaodev


[b][c][FF0000]-----------------------------------""",uid
                            )
                        )
                else:
                    pass  


                    

#################################
                

            if "1200" in data.hex()[0:4] and b"/admin" in data:
                i = re.split("/admin", str(data))[1]
                if "***" in i:
                    i = i.replace("***", "106")
                sid = str(i).split("(\\x")[0]
                json_result = get_available_room(data.hex()[10:])
                
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]
                clients.send(
                    self.GenResponsMsg(
                        f"""
[b][c][FF0000]-----------------------------------

[b][c][FFA500]- This bot was developed by  :  \n
[C][B][ffffff]- Con B Team \n
[b][c][FFA500]- Our Tiktok account : 
[b][c][FFFFFF]tiktok : tranbaodev
[C][B][ffffff]- t l g rm: @tranbaodev

[b][c][FF0000]-----------------------------------""", uid
                    )
                )
            


                        
            if "1200" in data.hex()[0:4] and b"/TOGBOT" in data:
                i = re.split("/TOGBOT", str(data))[1]
                if "***" in i:
                    i = i.replace("***", "106")
                sid = str(i).split("(\\x")[0]
                json_result = get_available_room(data.hex()[10:])
                
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]
                clients.send(
                    self.GenResponsMsg(
                        f"""
[b][c][FF0000]-----------------------------------  

[C][B][ffffff] -  Con B

[C][B][ffffff] -  Dev By Gia Bao 

[b][c][FF0000]-----------------------------------""", uid
                    )
                )
#################################
                            
                                
                                        

            if "1200" in data.hex()[0:4] and b"/5" in data:
                i = re.split("/5", str(data))[1]
                if "***" in i:
                    i = i.replace("***", "106")
                sid = str(i).split("(\\x")[0]
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)

                # إنشاء الفريق
                packetmaker = self.skwad_maker()
                socket_client.send(packetmaker)

                sleep(1)

                # تعيين نوع الفريق
                packetfinal = self.changes(4)
                socket_client.send(packetfinal)

                room_data = None
                if b'(' in data:
                    split_data = data.split(b'/5')
                    if len(split_data) > 1:
                        room_data = split_data[1].split(b'(')[0].decode().strip().split()
                        if room_data:
                            iddd = room_data[0]
                        else:
                            uid = parsed_data["5"]["data"]["1"]["data"]
                            iddd = parsed_data["5"]["data"]["1"]["data"]

                # إرسال الدعوة
                invitess = self.invite_skwad(iddd)
                socket_client.send(invitess)

                if uid:
                    clients.send(
                        self.GenResponsMsg(
                            f"{generate_random_color()}-----------------------------------\n\n- The order has been received and a team of 5 people is being formed\n\n-----------------------------------", uid
                        )
                    )

                # التأكد من المغادرة بعد 5 ثوانٍ إذا لم تتم المغادرة تلقائيًا
                sleep(4)
                print("Checking if still in squad...")

                leavee = self.leave_s()
                socket_client.send(leavee)

                 # تأخير أطول للتأكد من تنفيذ المغادرة قبل تغيير الوضع
                sleep(5)

                 # إرسال أمر تغيير وضع اللعبة إلى Solo
                change_to_solo = self.changes(1)  # تأكد أن `1` هو القيمة الصحيحة لـ Solo
                socket_client.send(change_to_solo)

                 # تأخير بسيط قبل إرسال التأكيد للمستخدم
                sleep(1)

                clients.send(
                     self.GenResponsMsg(
                         f"{generate_random_color()}-----------------------------------\n\n- Successfully left squad ! Now in Solo mode\n\n-----------------------------------", uid
                     )
                 )

                



#################################


  
            if "1200" in data.hex()[0:4] and b"/inv" in data:
                i = re.split("/inv", str(data))[1]
                if "***" in i:
                    i = i.replace("***", "106")
                sid = str(i).split("(\\x")[0]
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                split_data = re.split(rb'/inv', data)
                room_data = split_data[1].split(b'(')[0].decode().strip().split()
                if room_data:
                    print(room_data)
                    iddd = room_data[0]
                    numsc1 = room_data[1] if len(room_data) > 1 else None

                    if numsc1 is None:
                        clients.send(
                            self.GenResponsMsg(
                                f"{generate_random_color()}-----------------------------------\n\n- Please write id and count of the group\n\n[ffffff]Example : \n/ inv 2462c]046[c]863 4\n\n[b][c][FF0000]-----------------------------------", uid
                            )
                        )
                    else:
                        numsc = int(numsc1) - 1
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        if int(numsc1) < 3 or int(numsc1) > 6:
                            clients.send(
                                self.GenResponsMsg(
                                    f"{generate_random_color()}-----------------------------------\n\n- Please write id and count of the group\n\n[ffffff]Example : \n/ inv 2462c]046[c]863 4\n\n[b][c][FF0000]-----------------------------------", uid
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
                                    f"{generate_random_color()}-----------------------------------\n\n- AcCept The Invite QuickLy ! \n\n-----------------------------------", uid
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
                                            f"{generate_random_color()}-----------------------------------\n\nsucces !\n\n-----------------------------------", uid
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
                                            f"{generate_random_color()}-----------------------------------\n\n- Please accept the invite ! \n\n-----------------------------------", uid
                                        )
                                    )   
                else:
                    clients.send(
                        self.GenResponsMsg(
                            f"{generate_random_color()}-----------------------------------\n\n- Please write id and count of the group\n\n[ffffff]Example : \n/ inv 2462c]046[c]863 4\n\n[b][c][FF0000]-----------------------------------", uid
                        )
                    )   
                    



#################################




            if "1200" in data.hex()[0:4] and b"/6" in data:
                i = re.split("/6", str(data))[1]
                if "***" in i:
                    i = i.replace("***", "106")
                sid = str(i).split("(\\x")[0]
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                packetmaker = self.skwad_maker()
                socket_client.send(packetmaker)
                sleep(0.5)
                packetfinal = self.changes(5)
                room_data = None
                if b'(' in data:
                    split_data = data.split(b'/6')
                    if len(split_data) > 1:
                        room_data = split_data[1].split(b'(')[0].decode().strip().split()
                        if room_data:
                        	iddd= room_data[0]
                        else:
                        	uid = parsed_data["5"]["data"]["1"]["data"]
                        	iddd=parsed_data["5"]["data"]["1"]["data"]
                socket_client.send(packetfinal)            
                invitess = self.invite_skwad(iddd)
                socket_client.send(invitess)
                if uid:
	                clients.send(
	                    self.GenResponsMsg(
	                        f"{generate_random_color()}-----------------------------------\n\n- The order has been received and a team of 6 people is being formed\n\n-----------------------------------", uid
	                    )
	                )
                leaveee1 = True
                while leaveee1:
                    if leaveee == True:
                        print("Leave")
                        leavee = self.leave_s()
                        socket_client.send(leavee)   
                        leaveee = False
                        leaveee1 = False
                        clients.send(
                            self.GenResponsMsg(
                                f"{generate_random_color()}-----------------------------------\n\n- Successfully left squad! Now in Solo mode\n\n-----------------------------------", uid
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
                                f"[C][B] [FF00FF]-----------------------------------\n\n- Please accept the invite !\n\n-----------------------------------", uid
                            )
                        )
                        
                        
                        
#################################


                        
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
                        clients.send(self.GenResponsMsg("[C][B][FF0000]-----------------------------------\n\n- Please enter the player ID !\n\n-----------------------------------", uid))  
                except Exception as e:
                    print(f"Error in /st command: {e}")
                    clients.send(self.GenResponsMsg("[C][B][FF0000]-----------------------------------\n\n- The Bot Restarted Successfully !\n\n-----------------------------------", uid))
                
  
             
                                   
#################################

                    
            if "1200" in data.hex()[0:4] and b"/room" in data:
                i = re.split("/room", str(data))[1] 
                sid = str(i).split("(\\x")[0]
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]
                split_data = re.split(rb'/room', data)
                room_data = split_data[1].split(b'(')[0].decode().strip().split()
                if room_data:
                    
                    player_id = room_data[0]
                    if player_id.isdigit():
                        if "***" in player_id:
                            player_id = rrrrrrrrrrrrrr(player_id)
                        packetmaker = self.createpacketinfo(player_id)
                        socket_client.send(packetmaker)
                        sleep(0.5)
                        if "IN ROOM" in tempdata:
                            room_id = get_idroom_by_idplayer(data22)
              
                            custom_name = "GIABAODEV"
                             
                        if len(room_data) > 1:
                            custom_name = " ".join(room_data[1:]) 

                            packetspam = self.spam_room(room_id, player_id, custom_name) 
                            print(packetspam.hex())
                            
                            clients.send(
                                self.GenResponsMsg(
                                    f"{generate_random_color()}-----------------------------------\n\n- Spam Started For Uid : {fix_num(player_id)} !\n\n- With Name  : {custom_name} \n\n-----------------------------------", uid
                                )
                            )
                            
                            
                            for _ in range(50):

                                print(" Sending spam to "+player_id)
                                threading.Thread(target=socket_client.send, args=(packetspam,)).start()
                            #socket_client.send(packetspam)
                            
                            
                            
                            clients.send(
                                self.GenResponsMsg(
                                    f"{generate_random_color()}-----------------------------------\n\n- Done Spam Sent !\n\n-----------------------------------", uid
                                )
                            )
                        else:
                            clients.send(
                                self.GenResponsMsg(
                                    f"{generate_random_color()}-----------------------------------\n\n- The player is not in room ! \n\n-----------------------------------", uid
                                )
                            )      
                    else:
                        clients.send(
                            self.GenResponsMsg(
                                f"{generate_random_color()}-----------------------------------\n\n- Please write the id of player not !\n\n-----------------------------------", uid
                            )
                        )   

                else:
                    clients.send(
                        self.GenResponsMsg(
                            f"{generate_random_color()}-----------------------------------\n\n- Please write the id of player !\n\n-----------------------------------", uid
                        )
                    )  
            

            
            

            if "1200" in data.hex()[0:4] and b"WELCOME TO BOT" in data:
            	pass
            else:




#################################

             
	            
	            import requests	
	            if "1200" in data.hex()[0:4] and b"/spam" in data:
	                   json_result = get_available_room(data.hex()[10:])
	                   parsed_data = json.loads(json_result)
	                   uid = parsed_data["5"]["data"]["1"]["data"]

    
	                   color = generate_random_color()
	                   clients.send(self.GenResponsMsg(f"{generate_random_color()}-----------------------------------\n\n- Okay Sir, Please Wait....\n\n-----------------------------------", uid))


	                   command_split = re.split(r"/spam", str(data))
	                   player_id = command_split[1].split('(')[0].strip()
	                   print(player_id)

  
	                   spam_response = send_spam(player_id)
	                   print(spam_response) 

    
	                   clients.send(self.GenResponsMsg(spam_response, uid))

	                    
	                    

#################################


	            if "1200" in data.hex()[0:4] and b"/like" in data:
	                   	json_result = get_available_room(data.hex()[10:])
	                   	parsed_data = json.loads(json_result)
	                   	uid = parsed_data["5"]["data"]["1"]["data"]
    
	                   	clients.send(
	                   	self.GenResponsMsg(
            f"{generate_random_color()}-----------------------------------\n\n- Okay Sir, Please Wait....\n\n-----------------------------------", uid
        )
    )
	                   	command_split = re.split(r"/like", str(data))
	                   	player_id = command_split[1].split('(')[0].strip()
	                   	print(player_id)

	                   	likes_response = likes_plus(player_id)
	                   	print(likes_response) 

	                   	clients.send(self.GenResponsMsg(likes_response, uid))	            	



#################################

	            	
	            	
	            if "1200" in data.hex()[0:4] and b"/check" in data:
	                   try:
	                   	print("Received /ktra command")
	                   	command_split = re.split("/check", str(data))
	                   	json_result = get_available_room(data.hex()[10:])
	                   	parsed_data = json.loads(json_result)
	                   	uid = parsed_data["5"]["data"]["1"]["data"]
	                   	clients.send(
	                   	self.GenResponsMsg(
                            f"{generate_random_color()}-----------------------------------\n\n- Okay Sir, Please Wait.... \n\n-----------------------------------", uid
                        )
                    )
	                   	if len(command_split) > 1:
	                   	   player_id = command_split[1].split("\\x")[0].strip()
	                   	   player_id = command_split[1].split('(')[0].strip()
	                   	   print(player_id)

	                   	   banned_status = check_banned_status(player_id)
	                   	   print(banned_status)
	                   	   player_id = fix_num(player_id)
	                   	   status = banned_status.get('status', 'Unknown')
	                   	   player_name = banned_status.get('player_name', 'Unknown')

	                   	   response_message = (
                            f"{generate_random_color()}-----------------------------------\n\n- Name : {player_name}\n"
                            f"- Player ID : {player_id}\n"
                            f"- Status: {status}\n\n-----------------------------------"
                        )
	                   	   print(response_message)
	                   	   clients.send(self.GenResponsMsg(response_message, uid))
	                   except Exception as e:
	                   	print(f"Error in /check command: {e}")
	                   	clients.send(self.GenResponsMsg("[C][B][FF0000]- An error occurred, but the bot is still running !", uid))


	                   	
#################################

	                   	
	                   	
	            if "1200" in data.hex()[0:4] and b"/help" in data:
	                
	                lines = "_"*20
	                
	                json_result = get_available_room(data.hex()[10:])
	                parsed_data = json.loads(json_result)
	                user_name = parsed_data['5']['data']['9']['data']['1']['data']
	                uid = parsed_data["5"]["data"]["1"]["data"]
	                if "***" in str(uid):
	                	uid = rrrrrrrrrrrrrr(uid)
	                
	                print(f"\nUser With ID : {uid}\nName : {user_name}\nStarted Help\n")
	                
	                clients.send(
		                    self.GenResponsMsg(
		                        f"""
[b][c][FF0000]-----------------------------------
[C][B][00FFFF]-  BoT Commands :
[C][B][FFA500]-  5 In Squad :
[C][B][FFFFFF]-  / 5
[C][B][FFA500]-  6 In Squad :
[C][B][FFFFFF]-  / 6
[C][B][FFA500]-  Send 5 To PLayer :
[C][B][FFFFFF]-  / 5 <id>
[C][B][FFA500]-  Send 6 To PLayer 
[C][B][FFFFFF]-  / 6 <id>
[C][B][FFA500]-  Add Likes For The player :
[C][B][FFFFFF]-  / like <id>
[C][B][FFA500]-  Bring player to the team :
[C][B][FFFFFF]-  / inv <id> <4> 
""", uid
		                    )
		                )


	                clients.send(
		                    self.GenResponsMsg(
		                        f"""
[C][B][FFA500]-  Spam Friend Requests : 
[C][B][FFFFFF]- / spam <id>	
[C][B][FFA500]-  Spam Player Room  :	
[C][B][FFFFFF]- / room <id> <name>
[C][B][FFA500]-  Status Player Info :
[C][B][FFFFFF]- / status <id>
[C][B][FFA500]-  Kiem Tra Player Band  :
[C][B][FFFFFF]- / ktra <id>
[C][B][FFA500]-  Talk to Chat Gpt  :
[C][B][FFFFFF]- / ai <msg> 
[C][B][FFA500]-  Show Admins List :
[C][B][FFFFFF]- / admin
[b][c][FF0000]-----------------------------------

           BOT BY CON BO
          
[b][c][FF0000]-----------------------------------

""", uid
		                    )
		                )
		                	            
		                

	            if "1200" in data.hex()[0:4] and b"/ai" in data:
	                i = re.split("/ai", str(data))[1]
	                if "***" in i:
	                    i = i.replace("***", "106")
	                sid = str(i).split("(\\x")[0].strip()
	                headers = {"Content-Type": "application/json"}
	                payload = {
	                    "contents": [
	                        {
	                            "parts": [
	                                {"text": sid}
	                            ]
	                        }
	                    ]
	                }
	                response = requests.post(
	                    f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=AIzaSyDZvi8G_tnMUx7loUu51XYBt3t9eAQQLYo",
	                    headers=headers,
	                    json=payload,
	                )
	                if response.status_code == 200:
	                    ai_data = response.json()
	                    ai_response = ai_data['candidates'][0]['content']['parts'][0]['text']
	                    json_result = get_available_room(data.hex()[10:])
	                    parsed_data = json.loads(json_result)
	                    uid = parsed_data["5"]["data"]["1"]["data"]
	                    clients.send(
	                        self.GenResponsMsg(
	                            ai_response, uid
	                        )
	                    )
	                else:
	                    print("Error with AI API:", response.status_code, response.text)
	                    
                    
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
        payload = bytes.fromhex("1a13323032352d30352d32342031333a31373a3239220966726565206669726528013a07312e3131312e34423f416e64726f6964204f5320372e312e32202f204150492d323520284e32473438482f72656c2e73652e696e6672612e32303230303733302e313530353235294a0848616e6468656c6452035346525a045749464960b60a68ee0572033330307a1f41524d7637205646507633204e454f4e20564d48207c2032343030207c20338001e50f8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e309a012b476f6f676c657c65636332636334612d363364342d346539312d616563642d326264333565363966646663a2010b39312e3136372e352e3639aa0102656eb201203933343464333837383732646236346166373031393134346430646366366366ba010134c2010848616e6468656c64ca01104173757320415355535f493030334444ea014035613136366133613263383636366262373236373766376534313066636564343539643465383538646162623237383566633166663765393033656236326462f00101ca0203534652d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003e27de803ae63f003cf0bf803a0038004ed688804e27d9004ed689804e27dc80401d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138333936b205094f70656e474c455332b805ff7fc00504e005c28d01ea0507616e64726f6964f2055c4b717348542b33536e7459493045596348637155726c6c3431616f4b3531754550715759474e627a444b57356b6d2b4436373946787a5170305134556641502b74472f7650746b426670474f6c54596b784f7a2b474b4d59434d773df805fbe4068806019006019a060134a2060134b206221056164e535b58014e575c400a05415944695c045c5559690d505b6b550a3a0f0564")
        payload = payload.replace(b"2025-05-24 13:17:29", str(now).encode())
        payload = payload.replace(b"5a166a3a2c8666bb72677f7e410fced459d4e858dabb2785fc1ff7e903eb62db", NEW_ACCESS_TOKEN.encode("UTF-8"))
        payload = payload.replace(b"9344d387872db64af7019144d0dcf6cf", NEW_EXTERNAL_ID.encode("UTF-8"))
        payload = payload.replace(b"7428b253defc164018c604a1ebbfebdf", SIGNATURE_MD5.encode("UTF-8"))
        PAYLOAD = payload.hex()
        PAYLOAD = encrypt_api(PAYLOAD)
        PAYLOAD = bytes.fromhex(PAYLOAD)
        ip,port = self.GET_LOGIN_DATA(JWT_TOKEN , PAYLOAD)
        return ip,port
    
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
            'ReleaseVersion': 'OB49',
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
                response = requests.post(url, headers=headers, data=PAYLOAD,verify=False)
                response.raise_for_status()
                x = response.content.hex()
                json_result = get_available_room(x)
                parsed_data = json.loads(json_result)
                print(parsed_data)
                address = parsed_data['32']['data']
                ip = address[:len(address) - 6]
                port = address[len(address) - 5:]
                return ip, port
            
            except requests.RequestException as e:
                print(f"Request failed: {e}. Attempt {attempt + 1} of {max_retries}. Retrying...")
                attempt += 1
                time.sleep(2)

        print("Failed to get login data after multiple attempts.")
        return None, None

    def guest_token(self,uid , password):
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {"Host": "100067.connect.garena.com","User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)","Content-Type": "application/x-www-form-urlencoded","Accept-Encoding": "gzip, deflate, br","Connection": "close",}
        data = {"uid": f"{uid}","password": f"{password}","response_type": "token","client_type": "2","client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3","client_id": "100067",}
        response = requests.post(url, headers=headers, data=data)
        data = response.json()
        NEW_ACCESS_TOKEN = data['access_token']
        NEW_OPEN_ID = data['open_id']
        OLD_ACCESS_TOKEN = "5a166a3a2c8666bb72677f7e410fced459d4e858dabb2785fc1ff7e903eb62db"
        OLD_OPEN_ID = "9344d387872db64af7019144d0dcf6cf"
        time.sleep(0.2)
        data = self.TOKEN_MAKER(OLD_ACCESS_TOKEN , NEW_ACCESS_TOKEN , OLD_OPEN_ID , NEW_OPEN_ID,uid)
        return(data)
        
    def TOKEN_MAKER(self,OLD_ACCESS_TOKEN , NEW_ACCESS_TOKEN , OLD_OPEN_ID , NEW_OPEN_ID,id):
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB49',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Content-Length': '928',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.common.ggbluefox.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        data = bytes.fromhex('1a13323032352d30352d32342031333a31373a3239220966726565206669726528013a07312e3131312e34423f416e64726f6964204f5320372e312e32202f204150492d323520284e32473438482f72656c2e73652e696e6672612e32303230303733302e313530353235294a0848616e6468656c6452035346525a045749464960b60a68ee0572033330307a1f41524d7637205646507633204e454f4e20564d48207c2032343030207c20338001e50f8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e309a012b476f6f676c657c65636332636334612d363364342d346539312d616563642d326264333565363966646663a2010b39312e3136372e352e3639aa0102656eb201203933343464333837383732646236346166373031393134346430646366366366ba010134c2010848616e6468656c64ca01104173757320415355535f493030334444ea014035613136366133613263383636366262373236373766376534313066636564343539643465383538646162623237383566633166663765393033656236326462f00101ca0203534652d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003e27de803ae63f003cf0bf803a0038004ed688804e27d9004ed689804e27dc80401d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138333936b205094f70656e474c455332b805ff7fc00504e005c28d01ea0507616e64726f6964f2055c4b717348542b33536e7459493045596348637155726c6c3431616f4b3531754550715759474e627a444b57356b6d2b4436373946787a5170305134556641502b74472f7650746b426670474f6c54596b784f7a2b474b4d59434d773df805fbe4068806019006019a060134a2060134b206221056164e535b58014e575c400a05415944695c045c5559690d505b6b550a3a0f0564')
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
            ip,port =self.GET_PAYLOAD_BY_DATA(BASE64_TOKEN,NEW_ACCESS_TOKEN,1)
            self.key = key
            self.iv = iv
            print(key, iv)
            return(BASE64_TOKEN,key,iv,combined_timestamp,ip,port)
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
        token, key, iv, Timestamp, ip, port = self.guest_token(self.id, self.password)
        g_token = token
        print(ip, port)
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
        self.connect(token, ip, port, 'anything', key, iv)
        
      
        return token, key, iv
        
with open('accs.txt', 'r') as file:
    data = json.load(file)
ids_passwords = list(data.items())
def run_client(id, password):
    print(f"ID: {id}, Password: {password}")
    client = FF_CLIENT(id, password)
    client.start()

def restart_connection():
    global clients
    try:
        print("🔄 إعادة الاتصال...")
        clients.close()
        time.sleep(0.5)  # انتظار 3 ثوانٍ قبل المحاولة مجددًا
        client = FF_CLIENT(id="3997425651", password="19026B0D27D82F0FFCD57EB6EFBF012944C3FE357DC7E0CC32EE68D966633674")
        client.start()
    except Exception as e:
        print(f"⚠️ خطأ أثناء إعادة الاتصال: {e}")    


        
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
        client_thread = FF_CLIENT(id="3997425651", password="19026B0D27D82F0FFCD57EB6EFBF012944C3FE357DC7E0CC32EE68D966633674")
        client_thread.start()
    except Exception as e:
        logging.error(f"Error occurred: {e}")
        restart_program()

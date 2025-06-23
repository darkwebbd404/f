import requests
import jwt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3
import json

# تعطيل تحذيرات SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def encrypt_api(plain_text):
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(bytes.fromhex(plain_text), AES.block_size))
    return cipher_text.hex()

def TOKEN_MAKER(OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, uid):
    try:
        # إعداد البايلود
        payload_template = bytes.fromhex('1a13323032342d31322d30352031313a31393a3535220966726565206669726528013a07312e3130382e334242416e64726f6964204f532039202f204150492d32382028505133412e3139303830312e3030322f656e672e666f6c6c6f772e32303139303931362e313630393036294a0848616e6468656c645a045749464960b60a68c10672033234307a1d41524d3634204650204153494d4420414553207c2031363930207c203880019c0e8a01094d616c692d5438333092013e4f70656e474c20455320332e322076312e72323270302d303172656c302e6232616163353133316361653639643761303432356464353162386639626364a2010c34352e3234332e31302e3632aa0102656eb201206533326661626664333366643365356430633139353437623133373237636239ba010134c2010848616e6468656c64ca010f73616d73756e6720534d2d54353835ea014031663136346231343961363138653365306337373233326430383931333736356337623131633364383665653231626235343165373937636431313439353164f00101d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e00395c601e803e218f003c316f803c4088004e218880495c6019004e218980495c601c80401d2043f2f646174612f6170702f636f6d2e6474732e667265656669726574682d336f4669564137526f31634a423858795339503352413d3d2f6c69622f61726d3634e00401ea045f35623839326161616264363838653537316636383830353331313861313632627c2f646174612f6170702f636f6d2e6474732e667265656669726574682d336f4669564137526f31634a423858795339503352413d3d2f626173652e61706bf00403f804028a050236349a050a32303139313137383633b205094f70656e474c455332b805ff7fc00504ca050940004c17535b0f5130e005e0c701ea0507616e64726f6964f2055c4b71734854367033557276565042647073486772496573456b63424255794a6f4d544b6d4e315445646542794b722b454e376d6b2b3550476e483171376448365767586564324e343350744c4152372b6472377734396b4a5a77413df8058de4068806019006019a060134a2060134')  # أضف البايلود الكامل هنا
        modified_payload = (
            payload_template
            .replace(OLD_OPEN_ID.encode(), NEW_OPEN_ID.encode())
            .replace(OLD_ACCESS_TOKEN.encode(), NEW_ACCESS_TOKEN.encode())
        )
        
        # تشفير البايلود
        encrypted_payload = encrypt_api(modified_payload.hex())
        final_payload = bytes.fromhex(encrypted_payload)
        
        # إعداد الهيدرات
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB48',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ.eyJhY2NvdW50X2lkIjo5MjgwODkyMDE4LCJuaWNrbmFtZSI6IkJZVEV2R3QwIiwibm90aV9yZWdpb24iOiJNRSIsImxvY2tfcmVnaW9uIjoiTUUiLCJleHRlcm5hbF9pZCI6ImYzNGQyMjg0ZWJkYmFkNTkzNWJjOGI1NTZjMjY0ZmMwIiwiZXh0ZXJuYWxfdHlwZSI6NCwicGxhdF9pZCI6MCwiY2xpZW50X3ZlcnNpb24iOiIxLjEwNS41IiwiZW11bGF0b3Jfc2NvcmUiOjAsImlzX2VtdWxhdG9yIjpmYWxzZSwiY291bnRyeV9jb2RlIjoiRUciLCJleHRlcm5hbF91aWQiOjMyMzQ1NDE1OTEsInJlZ19hdmF0YXIiOjEwMjAwMDAwNSwic291cmNlIjoyLCJsb2NrX3JlZ2lvbl90aW1lIjoxNzE0NjYyMzcyLCJjbGllbnRfdHlwZSI6MSwic2lnbmF0dXJlX21kNSI6IiIsInVzaW5nX3ZlcnNpb24iOjEsInJlbGVhc2VfY2hhbm5lbCI6ImlvcyIsInJlbGVhc2VfdmVyc2lvbiI6Ik9CNDUiLCJleHAiOjE3MjIwNTkxMjF9.yYQZX0GeBMeBtMLhyCjSV0Q3e0jAqhnMZd3XOs6Ldk4',  # تحديث التوكن هنا
            'Content-Length': '928',  # القيمة الثابتة المطلوبة
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.common.ggbluefox.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        
        # إرسال الطلب
        URL = "https://loginbp.common.ggbluefox.com/MajorLogin"
        response = requests.post(URL, headers=headers, data=final_payload, verify=False)
        
        print("Response Status:", response.status_code)
        print("Response Text:", response.text)
        
        # معالجة الاستجابة
        if response.status_code == 200:
            if len(response.text) < 10:
                return False
            
            # استخراج التوكن من النص
            BASE64_TOKEN = response.text[response.text.find("eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ"):-1]
            second_dot_index = BASE64_TOKEN.find(".", BASE64_TOKEN.find(".") + 1)
            BASE64_TOKEN = BASE64_TOKEN[:second_dot_index+44]
            
            # فك تشفير التوكن
            decoded_token = jwt.decode(BASE64_TOKEN, options={"verify_signature": False})
            print("Decoded Token:", decoded_token)
            return True
            
        return False
        
    except Exception as e:
        print("Error in TOKEN_MAKER:", str(e))
        return False

def check_token(uid, password):
    try:
        # الحصول على التوكنات من جارينا
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close"
        }
        data = {
            "uid": uid,
            "password": password,
            "response_type": "token",
            "client_type": "2",
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067"
        }
        response = requests.post(url, headers=headers, data=data)
        auth_data = response.json()
        
        NEW_ACCESS_TOKEN = auth_data['access_token']
        NEW_OPEN_ID = auth_data['open_id']
        
        # القيم الثابتة القديمة
        OLD_ACCESS_TOKEN = "1f164b149a618e3e0c77232d08913765c7b11c3d86ee21bb541e797cd114951d"
        OLD_OPEN_ID = "e32fabfd33fd3e5d0c19547b13727cb9"
        
        # استدعاء الدالة الرئيسية
        return TOKEN_MAKER(OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, uid)
        
    except Exception as e:
        print("Error in check_token:", str(e))
        return False

if __name__ == "__main__":
    uid = "3842835346"
    password = "929E311D225B6E521CF0204A9D71147FBCC99EFA5D187E31DF598A842B82A91C"
    
    if check_token(uid, password):
        print(f"Success! Token info for {uid}:{password}")
    else:
        print(f"Failed! Check credentials for {uid}:{password}")
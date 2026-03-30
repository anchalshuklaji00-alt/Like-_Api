from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError
import base64
import time
from proto import FreeFire_pb2
from google.protobuf import json_format

app = Flask(__name__)

# Memory cache for Vercel 
MEMORY_TOKENS = []

# ============================================================
# JWT TOKEN GENERATOR LOGIC 
# ============================================================
def fetch_access_token_sync(cred_str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = cred_str + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    resp = requests.post(url, data=payload, headers=headers)
    data = resp.json()
    return data.get("access_token", ""), data.get("open_id", "")

def update_tokens(limit=10):
    """Generate naye tokens from uidpass.json aur memory/file me save kare"""
    global MEMORY_TOKENS
    try:
        with open("uidpass.json", "r") as f:
            accounts = json.load(f)

        new_tokens = []
        app.logger.info(f"Generating {limit} new JWT tokens...")
        for acc in accounts[:limit]:
            try:
                cred_str = f"uid={acc['uid']}&password={acc['password']}"
                access_token, open_id = fetch_access_token_sync(cred_str)
                if not access_token: continue

                login_req = FreeFire_pb2.LoginReq()
                json_format.ParseDict({
                    "open_id": open_id,
                    "open_id_type": "4",
                    "login_token": access_token,
                    "orign_platform_type": "4"
                }, login_req)
                proto_bytes = login_req.SerializeToString()

                MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
                MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
                cipher = AES.new(MAIN_KEY, AES.MODE_CBC, MAIN_IV)
                pad_len = AES.block_size - (len(proto_bytes) % AES.block_size)
                padded = proto_bytes + bytes([pad_len] * pad_len)
                encrypted = cipher.encrypt(padded)

                url = "https://loginbp.ggblueshark.com/MajorLogin"
                headers = {
                    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)",
                    "Content-Type": "application/octet-stream",
                    "X-Unity-Version": "2018.4.11f1",
                    "ReleaseVersion": "OB52"
                }
                resp = requests.post(url, data=encrypted, headers=headers)
                login_res = FreeFire_pb2.LoginRes()
                login_res.ParseFromString(resp.content)
                msg = json.loads(json_format.MessageToJson(login_res))
                token = msg.get('token')
                if token:
                    # NAYA FIX: Sirf token save hoga, "Bearer" nahi (purane tokens.json jaisa)
                    new_tokens.append({"token": token})
            except Exception as e:
                app.logger.error(f"Error generating token for {acc.get('uid')}: {e}")

        if new_tokens:
            MEMORY_TOKENS = new_tokens # Save to RAM
            try:
                # Agar likhne ki permission ho toh json file update karega
                with open("tokens.json", "w") as f:
                    json.dump(new_tokens, f, indent=4)
            except:
                pass
        return len(new_tokens)
    except Exception as e:
        app.logger.error(f"Error in update_tokens: {e}")
        return 0

# ============================================================
# MAIN API LOGIC (TUMHARA ORIGINAL CODE)
# ============================================================
def load_tokens():
    global MEMORY_TOKENS
    if MEMORY_TOKENS:
        return MEMORY_TOKENS
    try:
        with open("tokens.json", "r") as f:
            tokens = json.load(f)
        if tokens:
            MEMORY_TOKENS = tokens
            return tokens
    except Exception as e:
        app.logger.error(f"Error loading tokens: {e}")
    return []

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",  # Yahan Bearer add hota hai tumhari script me
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB52"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    return response.status
                return await response.text()
    except Exception as e:
        return None

async def send_multiple_requests(uid, server_name, url):
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None: return None
        
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None: return None
        
        tasks = []
        tokens = load_tokens()
        if not tokens: return None
        
        for i in range(100): # Tumhara original 100 requests wala loop
            token = tokens[i % len(tokens)]["token"]
            tasks.append(send_request(encrypted_uid, token, url))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    except Exception as e:
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except: return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    return encrypt_message(protobuf_data) if protobuf_data else None

def make_request(encrypt, server_name, token):
    try:
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"
        
        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB52"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False)
        if response.status_code != 200:
            return None
        
        hex_data = response.content.hex()
        binary = bytes.fromhex(hex_data)
        
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except Exception as e:
        app.logger.error(f"make_request error: {e}")
        return None

# ============================================================
# API ROUTES
# ============================================================
@app.route('/', methods=['GET'])
def index():
    return jsonify({
        "Developer": "Rolex",
        "message": "Welcome to the Self-Healing Rolex API",
        "status": "System Online",
        "endpoints": "/like?uid=<uid>&server_name=IND",
        "auto_cron": "/cron"
    })

# ⚡ VERCEL CRON ENDPOINT (SUBHA 4 BAJE KE LIYE) ⚡
@app.route('/cron', methods=['GET'])
def trigger_cron():
    count = update_tokens(10)
    return jsonify({"message": f"Cron successful. Generated {count} tokens.", "status": 200})

@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    if not uid: return jsonify({"error": "UID is required"}), 400

    try:
        # Load tokens
        tokens = load_tokens()
        
        # ⚡ AUTO HEAL: Agar tokens khali hain toh pehle generate karega
        if not tokens:
            update_tokens(5) 
            tokens = load_tokens()
            if not tokens:
                return jsonify({"error": "Failed to load or generate tokens."}), 500

        token = tokens[0]['token']
        server_name = request.args.get("server_name", "IND").upper()
        
        encrypted_uid = enc(uid)
        if not encrypted_uid: return jsonify({"error": "Encryption failed."}), 500

        # Step 1: Get before likes
        before = make_request(encrypted_uid, server_name, token)
        
        # ⚡ AUTO HEAL: Agar token expire ho gaya toh auto-refresh karega
        if before is None:
            update_tokens(5)
            tokens = load_tokens()
            if tokens:
                token = tokens[0]['token']
                before = make_request(encrypted_uid, server_name, token)
        
        if before is None:
            return jsonify({"error": "Failed to retrieve player info even after auto-refresh."}), 500
        
        data_before = json.loads(MessageToJson(before))
        before_like = int(data_before.get('AccountInfo', {}).get('Likes', 0) or 0)

        if server_name == "IND": url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif server_name in {"BR", "US", "SAC", "NA"}: url = "https://client.us.freefiremobile.com/LikeProfile"
        else: url = "https://clientbp.ggpolarbear.com/LikeProfile"

        # Step 2: Send likes using updated memory tokens
        requests_sent = asyncio.run(send_multiple_requests(uid, server_name, url))

        # Step 3: Check after likes
        after = make_request(encrypted_uid, server_name, token)
        if after is None: return jsonify({"error": "Failed to retrieve player info after likes."}), 500
        
        data_after = json.loads(MessageToJson(after))
        account_info = data_after.get('AccountInfo', {})
        after_like = int(account_info.get('Likes', 0) or 0)
        player_uid = int(account_info.get('UID', 0) or 0)
        player_name = str(account_info.get('PlayerNickname', ''))
        
        like_given = after_like - before_like
        
        return jsonify({
            "Developer": "Rolex ❤️‍🔥",
            "LikesGivenByAPI": like_given,
            "LikesafterCommand": after_like,
            "LikesbeforeCommand": before_like,
            "PlayerNickname": player_name,
            "Region": server_name,
            "UID": player_uid,
            "status": 1 if like_given > 0 else 2
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)

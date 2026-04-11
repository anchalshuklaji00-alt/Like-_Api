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
import warnings
from urllib3.exceptions import InsecureRequestWarning
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

app = Flask(__name__)

# ============================================================
# CONFIG
# ============================================================
RELEASE_VERSION = "OB53"
USER_AGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV  = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')

# Memory token cache
MEMORY_TOKENS = []
TOKEN_LAST_UPDATED = 0  # unix timestamp

# ============================================================
# TOKEN GENERATOR
# ============================================================

def fetch_access_token_sync(cred_str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = cred_str + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        "User-Agent": USER_AGENT,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    resp = requests.post(url, data=payload, headers=headers, verify=False, timeout=15)
    data = resp.json()
    return data.get("access_token", ""), data.get("open_id", "")


def update_tokens():
    """uidpass.json ke PURE accounts se tokens generate karo — NO LIMIT"""
    global MEMORY_TOKENS, TOKEN_LAST_UPDATED
    try:
        with open("uidpass.json", "r") as f:
            accounts = json.load(f)

        new_tokens = []
        failed = 0
        app.logger.info(f"[TOKEN] Total accounts: {len(accounts)} — generating tokens (OB53)...")

        for acc in accounts:  # ✅ No limit — sab accounts try honge
            try:
                cred_str = f"uid={acc['uid']}&password={acc['password']}"
                access_token, open_id = fetch_access_token_sync(cred_str)
                if not access_token:
                    app.logger.warning(f"[TOKEN] No access_token for {acc.get('uid')}")
                    failed += 1
                    continue

                login_req = FreeFire_pb2.LoginReq()
                json_format.ParseDict({
                    "open_id": open_id,
                    "open_id_type": "4",
                    "login_token": access_token,
                    "orign_platform_type": "4"
                }, login_req)
                proto_bytes = login_req.SerializeToString()

                cipher = AES.new(MAIN_KEY, AES.MODE_CBC, MAIN_IV)
                pad_len = AES.block_size - (len(proto_bytes) % AES.block_size)
                padded = proto_bytes + bytes([pad_len] * pad_len)
                encrypted = cipher.encrypt(padded)

                url = "https://loginbp.ggblueshark.com/MajorLogin"
                headers = {
                    "User-Agent": USER_AGENT,
                    "Content-Type": "application/octet-stream",
                    "X-Unity-Version": "2018.4.11f1",
                    "X-GA": "v1 1",
                    "ReleaseVersion": RELEASE_VERSION
                }
                resp = requests.post(url, data=encrypted, headers=headers, verify=False, timeout=15)

                if resp.status_code != 200:
                    app.logger.error(f"[TOKEN] MajorLogin {resp.status_code} for {acc.get('uid')}: {resp.content[:80]}")
                    failed += 1
                    continue

                login_res = FreeFire_pb2.LoginRes()
                login_res.ParseFromString(resp.content)
                msg = json.loads(json_format.MessageToJson(login_res))
                token = msg.get('token')

                if token:
                    new_tokens.append({"token": token})
                    app.logger.info(f"[TOKEN] ✅ uid {acc.get('uid')}")
                else:
                    app.logger.warning(f"[TOKEN] Empty token for {acc.get('uid')}")
                    failed += 1

            except Exception as e:
                app.logger.error(f"[TOKEN] Error for {acc.get('uid')}: {e}")
                failed += 1

        app.logger.info(f"[TOKEN] Done — Success: {len(new_tokens)}, Failed: {failed}")

        if new_tokens:
            MEMORY_TOKENS = new_tokens
            TOKEN_LAST_UPDATED = time.time()
            try:
                with open("tokens.json", "w") as f:
                    json.dump(new_tokens, f, indent=4)
                app.logger.info(f"[TOKEN] {len(new_tokens)} tokens saved to tokens.json")
            except Exception as e:
                app.logger.warning(f"[TOKEN] File save failed (RAM me saved): {e}")
        else:
            app.logger.error("[TOKEN] Koi token generate nahi hua!")

        return len(new_tokens), failed

    except Exception as e:
        app.logger.error(f"[TOKEN] update_tokens error: {e}")
        return 0, 0


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
        app.logger.error(f"[TOKEN] Load error: {e}")
    return []


def get_tokens_with_auto_refresh():
    """
    Smart token loader:
    - Khali hain → generate karo
    - 7 ghante purane hain → refresh karo
    - Valid hain → seedha return karo
    """
    global TOKEN_LAST_UPDATED
    tokens = load_tokens()

    if not tokens:
        app.logger.info("[TOKEN] Tokens khali — auto generating...")
        update_tokens()  # ✅ No limit
        tokens = load_tokens()

    elif TOKEN_LAST_UPDATED and (time.time() - TOKEN_LAST_UPDATED) > 25200:
        app.logger.info("[TOKEN] 7 ghante purane — auto refreshing...")
        update_tokens()  # ✅ No limit
        tokens = load_tokens()

    return tokens


# ============================================================
# CRYPTO + PROTOBUF HELPERS
# ============================================================

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv  = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = pad(plaintext, AES.block_size)
        return binascii.hexlify(cipher.encrypt(padded)).decode('utf-8')
    except Exception as e:
        app.logger.error(f"[CRYPTO] Encrypt error: {e}")
        return None


def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"[PROTO] Error: {e}")
        return None


def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except:
        return None


def enc(uid):
    protobuf_data = create_protobuf(uid)
    return encrypt_message(protobuf_data) if protobuf_data else None


# ============================================================
# LIKE SENDING
# ============================================================

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': USER_AGENT,
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': RELEASE_VERSION
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    return response.status
                return await response.text()
    except:
        return None


async def send_multiple_requests(uid, server_name, url):
    try:
        protobuf_message = create_protobuf_message(uid, server_name)
        if protobuf_message is None: return None

        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None: return None

        tokens = get_tokens_with_auto_refresh()
        if not tokens: return None

        tasks = []
        for i in range(100):
            token = tokens[i % len(tokens)]["token"]
            tasks.append(send_request(encrypted_uid, token, url))

        return await asyncio.gather(*tasks, return_exceptions=True)
    except:
        return None


# ============================================================
# PLAYER INFO
# ============================================================

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
            'User-Agent': USER_AGENT,
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': RELEASE_VERSION
        }
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=15)
        if response.status_code != 200:
            return None

        items = like_count_pb2.Info()
        items.ParseFromString(response.content)
        return items
    except Exception as e:
        app.logger.error(f"[INFO] make_request error: {e}")
        return None


# ============================================================
# ROUTES
# ============================================================

@app.route('/', methods=['GET'])
def index():
    token_count = len(load_tokens())
    age_hrs = round((time.time() - TOKEN_LAST_UPDATED) / 3600, 1) if TOKEN_LAST_UPDATED else "N/A"
    try:
        with open("uidpass.json", "r") as f:
            total_accounts = len(json.load(f))
    except:
        total_accounts = "N/A"
    return jsonify({
        "Developer": "Rolex",
        "status": "Online",
        "version": RELEASE_VERSION,
        "tokens_loaded": token_count,
        "total_accounts": total_accounts,
        "token_age_hours": age_hrs,
        "like_endpoint": "/like?uid=<uid>&server_name=IND",
        "refresh_endpoint": "/cron"
    })


@app.route('/cron', methods=['GET'])
def trigger_cron():
    """Manual ya scheduled cron se token refresh — PURE uidpass.json accounts"""
    count, failed = update_tokens()  # ✅ No limit — sab accounts
    return jsonify({
        "message": f"Token refresh done. Generated: {count}, Failed: {failed}",
        "tokens_generated": count,
        "tokens_failed": failed,
        "version": RELEASE_VERSION,
        "status": 200 if count > 0 else 500
    })


@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    if not uid:
        return jsonify({"error": "UID required"}), 400

    server_name = request.args.get("server_name", "IND").upper()

    try:
        # Step 1: Tokens lo
        tokens = get_tokens_with_auto_refresh()
        if not tokens:
            return jsonify({"error": "Token generate nahi hua. uidpass.json check karo."}), 500

        encrypted_uid = enc(uid)
        if not encrypted_uid:
            return jsonify({"error": "Encryption failed."}), 500

        # Step 2: Before likes fetch
        token = tokens[0]['token']
        before = make_request(encrypted_uid, server_name, token)

        # ⚡ Token expire hua → force refresh + retry
        if before is None:
            app.logger.warning("[LIKE] Token expired — force refresh kar raha hoon...")
            update_tokens()  # ✅ No limit
            tokens = load_tokens()
            if not tokens:
                return jsonify({"error": "Force refresh ke baad bhi token nahi mila."}), 500
            token = tokens[0]['token']
            before = make_request(encrypted_uid, server_name, token)

        if before is None:
            return jsonify({"error": "Player info nahi mila. UID / server_name check karo."}), 500

        data_before = json.loads(MessageToJson(before))
        before_like = int(data_before.get('AccountInfo', {}).get('Likes', 0) or 0)

        # Step 3: Like URL decide karo
        if server_name == "IND":
            like_url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            like_url = "https://client.us.freefiremobile.com/LikeProfile"
        else:
            like_url = "https://clientbp.ggpolarbear.com/LikeProfile"

        # Step 4: Likes bhejo
        asyncio.run(send_multiple_requests(uid, server_name, like_url))

        # Step 5: After likes fetch
        after = make_request(encrypted_uid, server_name, token)
        if after is None:
            return jsonify({"error": "Likes ke baad player info nahi mila."}), 500

        data_after    = json.loads(MessageToJson(after))
        account_info  = data_after.get('AccountInfo', {})
        after_like    = int(account_info.get('Likes', 0) or 0)
        player_uid    = int(account_info.get('UID', 0) or 0)
        player_name   = str(account_info.get('PlayerNickname', ''))
        like_given    = after_like - before_like

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
        app.logger.error(f"[LIKE] Route error: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)


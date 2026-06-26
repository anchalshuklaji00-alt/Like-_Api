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
import warnings
from urllib3.exceptions import InsecureRequestWarning
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

app = Flask(__name__)

# ============================================================
# CONFIG
# ============================================================
RELEASE_VERSION = "OB54"
USER_AGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"

# ============================================================
# SERVER CONFIG — har server ka alag uidpass + token file
# ============================================================
SERVER_CONFIG = {
    "IND": {
        "uidpass_file": "uidpass_ind.json",
        "token_file":   "token_ind.txt",
        "like_url":     "https://client.ind.freefiremobile.com/LikeProfile",
        "info_url":     "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
    },
    "BD": {
        "uidpass_file": "uidpass_bd.json",
        "token_file":   "token_bd.txt",
        "like_url":     "https://clientbp.ggpolarbear.com/LikeProfile",
        "info_url":     "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
    },
    "PAK": {
        "uidpass_file": "uidpass_pak.json",
        "token_file":   "token_pak.txt",
        "like_url":     "https://clientbp.ggpolarbear.com/LikeProfile",
        "info_url":     "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
    },
    "HAR": {
        "uidpass_file": "uidpass_har.json",
        "token_file":   "token_har.txt",
        "like_url":     "https://clientbp.ggpolarbear.com/LikeProfile",
        "info_url":     "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
    },
    # US / BR / NA / SAC ke liye bhi IND jaise add kar sakte ho
    "BR":  {
        "uidpass_file": "uidpass_br.json",
        "token_file":   "token_br.txt",
        "like_url":     "https://client.us.freefiremobile.com/LikeProfile",
        "info_url":     "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
    },
    "US":  {
        "uidpass_file": "uidpass_br.json",   # same as BR
        "token_file":   "token_br.txt",
        "like_url":     "https://client.us.freefiremobile.com/LikeProfile",
        "info_url":     "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
    },
    "SAC": {
        "uidpass_file": "uidpass_br.json",
        "token_file":   "token_br.txt",
        "like_url":     "https://client.us.freefiremobile.com/LikeProfile",
        "info_url":     "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
    },
    "NA":  {
        "uidpass_file": "uidpass_br.json",
        "token_file":   "token_br.txt",
        "like_url":     "https://client.us.freefiremobile.com/LikeProfile",
        "info_url":     "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
    },
}

# Per-server in-memory token cache
MEMORY_TOKENS = {s: [] for s in SERVER_CONFIG}
TOKEN_LAST_UPDATED = {s: 0 for s in SERVER_CONFIG}


# ============================================================
# TOKEN GENERATOR — per server
# ============================================================

def fetch_access_token_sync(uid, password):
    url = f"https://ff-ob54-jwt-api.vercel.app/guest_to_jwt?uid={uid}&password={password}"
    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        token = data.get("jwt_token") or data.get("access_token")
        return token
    except Exception as e:
        app.logger.error(f"[TOKEN] JWT fetch error for uid={uid}: {e}")
        return None


def update_tokens(server: str):
    """
    Ek specific server ke uidpass file se tokens generate karo.
    Return: (success_count, failed_count, failed_accounts_list)
    failed_accounts_list = [{"uid": ..., "password": ...}, ...]
    """
    global MEMORY_TOKENS, TOKEN_LAST_UPDATED

    server = server.upper()
    if server not in SERVER_CONFIG:
        app.logger.error(f"[TOKEN] Unknown server: {server}")
        return 0, 0, []

    cfg = SERVER_CONFIG[server]
    uidpass_file = cfg["uidpass_file"]
    token_file   = cfg["token_file"]

    try:
        with open(uidpass_file, "r") as f:
            accounts = json.load(f)
    except FileNotFoundError:
        app.logger.error(f"[TOKEN][{server}] File not found: {uidpass_file}")
        return 0, 0, []
    except Exception as e:
        app.logger.error(f"[TOKEN][{server}] File read error: {e}")
        return 0, 0, []

    new_tokens    = []
    failed_accs   = []   # ← failed uid+pass yahan store honge
    total         = len(accounts)

    app.logger.info(f"[TOKEN][{server}] Total accounts: {total} — generating tokens...")

    for acc in accounts:
        uid_val  = acc.get("uid", "?")
        pass_val = acc.get("password", "?")
        try:
            token = fetch_access_token_sync(uid_val, pass_val)

            if token:
                new_tokens.append({"token": token})
                app.logger.info(f"[TOKEN][{server}] ✅ uid={uid_val}")
            else:
                reason = "No token from JWT API"
                app.logger.warning(f"[TOKEN][{server}] ❌ {reason} → uid={uid_val}")
                failed_accs.append({"uid": uid_val, "password": pass_val, "reason": reason})

        except Exception as e:
            reason = str(e)
            app.logger.error(f"[TOKEN][{server}] ❌ Exception → uid={uid_val}: {reason}")
            failed_accs.append({"uid": uid_val, "password": pass_val, "reason": reason})

    success = len(new_tokens)
    failed  = len(failed_accs)
    app.logger.info(f"[TOKEN][{server}] Done — ✅ Success: {success}, ❌ Failed: {failed}/{total}")

    if new_tokens:
        MEMORY_TOKENS[server]       = new_tokens
        TOKEN_LAST_UPDATED[server]  = time.time()
        try:
            with open(token_file, "w") as f:
                json.dump(new_tokens, f, indent=4)
            app.logger.info(f"[TOKEN][{server}] {success} tokens → {token_file}")
        except Exception as e:
            app.logger.warning(f"[TOKEN][{server}] File save failed (RAM me saved): {e}")
    else:
        app.logger.error(f"[TOKEN][{server}] ⚠️ Koi token generate nahi hua!")

    return success, failed, failed_accs


def load_tokens(server: str):
    """Server ka token_file ya MEMORY_TOKENS se tokens load karo."""
    server = server.upper()
    if server not in SERVER_CONFIG:
        return []

    if MEMORY_TOKENS.get(server):
        return MEMORY_TOKENS[server]

    token_file = SERVER_CONFIG[server]["token_file"]
    try:
        with open(token_file, "r") as f:
            tokens = json.load(f)
        if tokens:
            MEMORY_TOKENS[server] = tokens
            return tokens
    except Exception as e:
        app.logger.error(f"[TOKEN][{server}] Load error: {e}")
    return []


def get_tokens_with_auto_refresh(server: str):
    """
    Smart loader:
    - Khali → generate karo
    - 7 ghante se purane → refresh karo
    - Valid → return karo
    """
    server = server.upper()
    tokens = load_tokens(server)

    if not tokens:
        app.logger.info(f"[TOKEN][{server}] Tokens khali — auto generating...")
        update_tokens(server)
        tokens = load_tokens(server)
    elif TOKEN_LAST_UPDATED.get(server) and (time.time() - TOKEN_LAST_UPDATED[server]) > 25200:
        app.logger.info(f"[TOKEN][{server}] 7 ghante purane — auto refreshing...")
        update_tokens(server)
        tokens = load_tokens(server)

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
        message.uid    = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"[PROTO] Error: {e}")
        return None


def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena  = 1
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
            'User-Agent':      USER_AGENT,
            'Connection':      "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization':   f"Bearer {token}",
            'Content-Type':    "application/x-www-form-urlencoded",
            'Expect':          "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA':            "v1 1",
            'ReleaseVersion':  RELEASE_VERSION
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    return response.status
                return await response.text()
    except:
        return None


async def send_multiple_requests(uid, server_name, url, tokens):
    try:
        protobuf_message = create_protobuf_message(uid, server_name)
        if protobuf_message is None:
            return None

        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            return None

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
        cfg = SERVER_CONFIG.get(server_name.upper())
        if cfg:
            url = cfg["info_url"]
        else:
            url = "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"

        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent':      USER_AGENT,
            'Connection':      "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization':   f"Bearer {token}",
            'Content-Type':    "application/x-www-form-urlencoded",
            'Expect':          "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA':            "v1 1",
            'ReleaseVersion':  RELEASE_VERSION
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
    server_status = {}
    for srv, cfg in SERVER_CONFIG.items():
        count = len(load_tokens(srv))
        age   = round((time.time() - TOKEN_LAST_UPDATED[srv]) / 3600, 1) if TOKEN_LAST_UPDATED.get(srv) else "N/A"
        try:
            with open(cfg["uidpass_file"], "r") as f:
                total_acc = len(json.load(f))
        except:
            total_acc = 0
        server_status[srv] = {
            "tokens_loaded":  count,
            "total_accounts": total_acc,
            "token_age_hours": age,
            "token_file":     cfg["token_file"],
            "uidpass_file":   cfg["uidpass_file"],
        }

    return jsonify({
        "Developer":        "Rolex",
        "status":           "Online",
        "version":          RELEASE_VERSION,
        "servers":          server_status,
        "like_endpoint":    "/like?uid=<uid>&server_name=IND",
        "refresh_endpoints": {
            "all":  "/cron",
            "IND":  "/cron/ind",
            "BD":   "/cron/bd",
            "PAK":  "/cron/pak",
            "HAR":  "/cron/har",
        }
    })


# ─── CRON: specific server refresh ───

def _run_cron_for_server(server: str):
    """Helper — ek server refresh karo aur response dict banao."""
    server = server.upper()
    if server not in SERVER_CONFIG:
        return {"error": f"Unknown server: {server}"}, 400

    success, failed, failed_accs = update_tokens(server)

    # failed_accs me uid+pass+reason hai — response me daal do
    return {
        "server":            server,
        "tokens_generated":  success,
        "tokens_failed":     failed,
        "failed_accounts":   failed_accs,   # ← uid, password, reason
        "version":           RELEASE_VERSION,
        "status":            200 if success > 0 else 500,
        "message":           (
            f"[{server}] Token refresh done. "
            f"✅ Generated: {success}, ❌ Failed: {failed}"
        )
    }, 200 if success > 0 else 500


@app.route('/cron', methods=['GET'])
def trigger_cron_all():
    """Sare servers refresh karo."""
    results = {}
    overall_ok = False
    for srv in SERVER_CONFIG:
        data, _ = _run_cron_for_server(srv)
        results[srv] = data
        if data.get("tokens_generated", 0) > 0:
            overall_ok = True
    return jsonify({
        "message": "All servers refresh complete.",
        "results": results,
        "status":  200 if overall_ok else 500
    }), 200 if overall_ok else 500


@app.route('/cron/ind', methods=['GET'])
def trigger_cron_ind():
    data, code = _run_cron_for_server("IND")
    return jsonify(data), code


@app.route('/cron/bd', methods=['GET'])
def trigger_cron_bd():
    data, code = _run_cron_for_server("BD")
    return jsonify(data), code


@app.route('/cron/pak', methods=['GET'])
def trigger_cron_pak():
    data, code = _run_cron_for_server("PAK")
    return jsonify(data), code


@app.route('/cron/har', methods=['GET'])
def trigger_cron_har():
    data, code = _run_cron_for_server("HAR")
    return jsonify(data), code


# ─── SAVE UID+PASS ROUTE ───

@app.route('/save', methods=['GET'])
def save_account():
    """
    Server ki uidpass file me naya account add karo.
    URL: /save?uid=12345&password=xxxxx&server=IND
    """
    uid_val  = request.args.get("uid", "").strip()
    pass_val = request.args.get("password", "").strip()
    server   = request.args.get("server", "").upper().strip()

    # ── Validation ──
    if not uid_val:
        return jsonify({"error": "❌ 'uid' parameter missing hai."}), 400
    if not pass_val:
        return jsonify({"error": "❌ 'password' parameter missing hai."}), 400
    if not server:
        return jsonify({"error": "❌ 'server' parameter missing hai. Example: server=IND"}), 400
    if server not in SERVER_CONFIG:
        return jsonify({
            "error":   f"❌ Unknown server '{server}'.",
            "valid_servers": list(SERVER_CONFIG.keys())
        }), 400

    uidpass_file = SERVER_CONFIG[server]["uidpass_file"]

    # ── File load karo (ya naya banao) ──
    try:
        with open(uidpass_file, "r") as f:
            accounts = json.load(f)
        if not isinstance(accounts, list):
            accounts = []
    except FileNotFoundError:
        accounts = []   # file nahi thi — naya banayenge
    except Exception as e:
        return jsonify({"error": f"❌ File read error: {e}"}), 500

    # ── Duplicate check ──
    for acc in accounts:
        if str(acc.get("uid", "")) == str(uid_val):
            return jsonify({
                "status":  "already_exists",
                "message": f"⚠️ UID {uid_val} pehle se '{uidpass_file}' me hai.",
                "server":  server,
                "uid":     uid_val
            }), 200

    # ── Append + Save ──
    accounts.append({"uid": uid_val, "password": pass_val})
    try:
        with open(uidpass_file, "w") as f:
            json.dump(accounts, f, indent=4)
    except Exception as e:
        return jsonify({"error": f"❌ File save error: {e}"}), 500

    app.logger.info(f"[SAVE][{server}] ✅ uid={uid_val} → {uidpass_file}")

    return jsonify({
        "status":        "saved",
        "message":       f"✅ UID {uid_val} successfully '{uidpass_file}' me save ho gaya.",
        "server":        server,
        "uid":           uid_val,
        "total_accounts": len(accounts),
        "note":          f"Token generate karne ke liye /cron/{server.lower()} chalao."
    }), 200


# ─── DELETE UID ROUTE ───

@app.route('/delete', methods=['GET'])
def delete_account():
    """
    Server ki uidpass file se koi UID remove karo.
    URL: /delete?uid=12345&server=IND
    """
    uid_val = request.args.get("uid", "").strip()
    server  = request.args.get("server", "").upper().strip()

    if not uid_val:
        return jsonify({"error": "❌ 'uid' parameter missing hai."}), 400
    if not server:
        return jsonify({"error": "❌ 'server' parameter missing hai."}), 400
    if server not in SERVER_CONFIG:
        return jsonify({
            "error":         f"❌ Unknown server '{server}'.",
            "valid_servers": list(SERVER_CONFIG.keys())
        }), 400

    uidpass_file = SERVER_CONFIG[server]["uidpass_file"]

    try:
        with open(uidpass_file, "r") as f:
            accounts = json.load(f)
        if not isinstance(accounts, list):
            accounts = []
    except FileNotFoundError:
        return jsonify({"error": f"❌ File '{uidpass_file}' exist nahi karta."}), 404
    except Exception as e:
        return jsonify({"error": f"❌ File read error: {e}"}), 500

    before_count = len(accounts)
    accounts = [a for a in accounts if str(a.get("uid", "")) != str(uid_val)]
    after_count  = len(accounts)

    if before_count == after_count:
        return jsonify({
            "status":  "not_found",
            "message": f"⚠️ UID {uid_val} '{uidpass_file}' me nahi mila.",
            "server":  server,
            "uid":     uid_val
        }), 404

    try:
        with open(uidpass_file, "w") as f:
            json.dump(accounts, f, indent=4)
    except Exception as e:
        return jsonify({"error": f"❌ File save error: {e}"}), 500

    app.logger.info(f"[DELETE][{server}] 🗑️ uid={uid_val} removed from {uidpass_file}")

    return jsonify({
        "status":         "deleted",
        "message":        f"🗑️ UID {uid_val} '{uidpass_file}' se remove ho gaya.",
        "server":         server,
        "uid":            uid_val,
        "total_accounts": after_count
    }), 200


# ─── LIST ACCOUNTS ROUTE ───

@app.route('/accounts', methods=['GET'])
def list_accounts():
    """
    Kisi server ke saved accounts dekho.
    URL: /accounts?server=IND
    """
    server = request.args.get("server", "").upper().strip()

    if not server:
        # Sare servers ka summary
        summary = {}
        for srv, cfg in SERVER_CONFIG.items():
            try:
                with open(cfg["uidpass_file"], "r") as f:
                    accs = json.load(f)
               .

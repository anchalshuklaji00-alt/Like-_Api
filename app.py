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

def fetch_access_token_sync(cred_str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = (
        cred_str
        + "&response_type=token"
        + "&client_type=2"
        + "&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
        + "&client_id=100067"
    )
    headers = {
        "User-Agent": USER_AGENT,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    resp = requests.post(url, data=payload, headers=headers, verify=False, timeout=15)
    data = resp.json()
    return data.get("access_token", ""), data.get("open_id", "")


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
            cred_str = f"uid={uid_val}&password={pass_val}"
            access_token, open_id = fetch_access_token_sync(cred_str)

            if not access_token:
                app.logger.warning(f"[TOKEN][{server}] ❌ No access_token → uid={uid_val}")
                failed_accs.append({"uid": uid_val, "password": pass_val, "reason": "No access_token"})
                continue

            login_req = FreeFire_pb2.LoginReq()
            json_format.ParseDict({
                "open_id":            open_id,
                "open_id_type":       "4",
                "login_token":        access_token,
                "orign_platform_type": "4"
            }, login_req)
            proto_bytes = login_req.SerializeToString()

            cipher  = AES.new(MAIN_KEY, AES.MODE_CBC, MAIN_IV)
            pad_len = AES.block_size - (len(proto_bytes) % AES.block_size)
            padded  = proto_bytes + bytes([pad_len] * pad_len)
            encrypted = cipher.encrypt(padded)

            url_login = "https://loginbp.ggblueshark.com/MajorLogin"
            headers   = {
                "User-Agent":      USER_AGENT,
                "Content-Type":    "application/octet-stream",
                "X-Unity-Version": "2018.4.11f1",
                "X-GA":            "v1 1",
                "ReleaseVersion":  RELEASE_VERSION
            }
            resp = requests.post(url_login, data=encrypted, headers=headers, verify=False, timeout=15)

            if resp.status_code != 200:
                reason = f"MajorLogin HTTP {resp.status_code}"
                app.logger.error(f"[TOKEN][{server}] ❌ {reason} → uid={uid_val}")
                failed_accs.append({"uid": uid_val, "password": pass_val, "reason": reason})
                continue

            login_res = FreeFire_pb2.LoginRes()
            login_res.ParseFromString(resp.content)
            msg   = json.loads(json_format.MessageToJson(login_res))
            token = msg.get("token")

            if token:
                new_tokens.append({"token": token})
                app.logger.info(f"[TOKEN][{server}] ✅ uid={uid_val}")
            else:
                reason = "Empty token from MajorLogin"
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
                summary[srv] = {
                    "total":    len(accs),
                    "file":     cfg["uidpass_file"],
                    "accounts": [{"uid": a.get("uid"), "password": a.get("password")} for a in accs]
                }
            except FileNotFoundError:
                summary[srv] = {"total": 0, "file": cfg["uidpass_file"], "accounts": []}
            except Exception as e:
                summary[srv] = {"error": str(e)}
        return jsonify({"all_servers": summary}), 200

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
        accounts = []
    except Exception as e:
        return jsonify({"error": f"❌ File read error: {e}"}), 500

    return jsonify({
        "server":   server,
        "file":     uidpass_file,
        "total":    len(accounts),
        "accounts": [{"uid": a.get("uid"), "password": a.get("password")} for a in accounts]
    }), 200


# ─── SERVER STATUS ROUTE ───

@app.route('/status', methods=['GET'])
def server_status():
    """
    Har server me kitne IDs aur kitne Tokens hain — full details ke saath.
    URL: /status          → sare servers ka status
    URL: /status?server=IND → sirf ek server ka status
    """
    server_param = request.args.get("server", "").upper().strip()

    def get_server_detail(srv):
        cfg = SERVER_CONFIG[srv]

        # ── IDs count from uidpass file ──
        try:
            with open(cfg["uidpass_file"], "r") as f:
                accounts = json.load(f)
            if not isinstance(accounts, list):
                accounts = []
            uid_list = [{"uid": a.get("uid"), "password": a.get("password")} for a in accounts]
            total_ids = len(accounts)
            ids_status = "✅ OK"
        except FileNotFoundError:
            uid_list   = []
            total_ids  = 0
            ids_status = "⚠️ File not found"
        except Exception as e:
            uid_list   = []
            total_ids  = 0
            ids_status = f"❌ Error: {e}"

        # ── Tokens count from memory / token file ──
        mem_tokens = MEMORY_TOKENS.get(srv, [])
        if mem_tokens:
            token_source = "memory (RAM)"
            tokens_list  = mem_tokens
        else:
            try:
                with open(cfg["token_file"], "r") as f:
                    tokens_list = json.load(f)
                if not isinstance(tokens_list, list):
                    tokens_list = []
                token_source = f"file ({cfg['token_file']})"
            except FileNotFoundError:
                tokens_list  = []
                token_source = "⚠️ Token file not found"
            except Exception as e:
                tokens_list  = []
                token_source = f"❌ Error: {e}"

        total_tokens = len(tokens_list)

        # ── Token age ──
        last_updated = TOKEN_LAST_UPDATED.get(srv, 0)
        if last_updated:
            age_seconds = round(time.time() - last_updated)
            age_hours   = round(age_seconds / 3600, 2)
            token_age   = f"{age_hours} hours ago"
        else:
            token_age = "Never refreshed / unknown"

        return {
            "server":        srv,
            "uidpass_file":  cfg["uidpass_file"],
            "token_file":    cfg["token_file"],
            "total_ids":     total_ids,
            "ids_status":    ids_status,
            "uid_list":      uid_list,
            "total_tokens":  total_tokens,
            "token_source":  token_source,
            "token_age":     token_age,
            "like_url":      cfg["like_url"],
            "info_url":      cfg["info_url"],
            "refresh_url":   f"/cron/{srv.lower()}",
            "summary":       f"📋 IDs: {total_ids} | 🔑 Tokens: {total_tokens}"
        }

    # ── Single server ──
    if server_param:
        if server_param not in SERVER_CONFIG:
            return jsonify({
                "error":         f"❌ Unknown server '{server_param}'.",
                "valid_servers": list(SERVER_CONFIG.keys())
            }), 400
        detail = get_server_detail(server_param)
        return jsonify(detail), 200

    # ── All servers ──
    all_status   = {}
    total_ids_all    = 0
    total_tokens_all = 0

    for srv in SERVER_CONFIG:
        detail = get_server_detail(srv)
        all_status[srv]   = detail
        total_ids_all    += detail["total_ids"]
        total_tokens_all += detail["total_tokens"]

    return jsonify({
        "Developer":       "Rolex ❤️‍🔥",
        "overall_summary": f"📋 Total IDs (all servers): {total_ids_all} | 🔑 Total Tokens (all servers): {total_tokens_all}",
        "total_ids_all_servers":    total_ids_all,
        "total_tokens_all_servers": total_tokens_all,
        "servers": all_status
    }), 200


# ─── LIKE ROUTE ───

@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    if not uid:
        return jsonify({"error": "UID required"}), 400

    server_name = request.args.get("server_name", "IND").upper()

    # Server valid hai?
    if server_name not in SERVER_CONFIG:
        return jsonify({
            "error": f"Unknown server '{server_name}'. Valid: {list(SERVER_CONFIG.keys())}"
        }), 400

    cfg = SERVER_CONFIG[server_name]

    try:
        # Step 1: Server ke tokens lo
        tokens = get_tokens_with_auto_refresh(server_name)

        if not tokens:
            # Token file exist nahi ya khali — server ke liye like nahi ja sakta
            return jsonify({
                "error":   f"❌ {server_name} server me like nahi ja sakta.",
                "reason":  f"'{cfg['token_file']}' me koi token nahi hai.",
                "fix":     f"Pehle /cron/{server_name.lower()} run karo tokens generate karne ke liye.",
                "server":  server_name,
                "status":  0
            }), 503

        encrypted_uid = enc(uid)
        if not encrypted_uid:
            return jsonify({"error": "Encryption failed."}), 500

        # Step 2: Before likes fetch
        token = tokens[0]['token']
        before = make_request(encrypted_uid, server_name, token)

        # Token expire hua → force refresh + retry
        if before is None:
            app.logger.warning(f"[LIKE][{server_name}] Token expired — force refresh...")
            update_tokens(server_name)
            tokens = load_tokens(server_name)
            if not tokens:
                return jsonify({
                    "error":  f"❌ {server_name} server me like nahi ja sakta.",
                    "reason": "Force refresh ke baad bhi token nahi mila.",
                    "server": server_name,
                    "status": 0
                }), 503
            token  = tokens[0]['token']
            before = make_request(encrypted_uid, server_name, token)

        if before is None:
            return jsonify({
                "error":  "Player info nahi mila. UID / server_name check karo.",
                "server": server_name
            }), 500

        data_before = json.loads(MessageToJson(before))
        before_like = int(data_before.get('AccountInfo', {}).get('Likes', 0) or 0)

        # Step 3: Likes bhejo — server ka like_url use karo
        like_url = cfg["like_url"]
        asyncio.run(send_multiple_requests(uid, server_name, like_url, tokens))

        # Step 4: After likes fetch
        after = make_request(encrypted_uid, server_name, token)
        if after is None:
            return jsonify({"error": "Likes ke baad player info nahi mila.", "server": server_name}), 500

        data_after   = json.loads(MessageToJson(after))
        account_info = data_after.get('AccountInfo', {})
        after_like   = int(account_info.get('Likes', 0) or 0)
        player_uid   = int(account_info.get('UID', 0) or 0)
        player_name  = str(account_info.get('PlayerNickname', ''))
        like_given   = after_like - before_like

        return jsonify({
            "Developer":        "Rolex ❤️‍🔥",
            "LikesGivenByAPI":  like_given,
            "LikesafterCommand": after_like,
            "LikesbeforeCommand": before_like,
            "PlayerNickname":   player_name,
            "Region":           server_name,
            "UID":              player_uid,
            "TokensUsed":       len(tokens),
            "TokenFile":        cfg["token_file"],
            "status":           1 if like_given > 0 else 2
        })

    except Exception as e:
        app.logger.error(f"[LIKE][{server_name}] Route error: {e}")
        return jsonify({"error": str(e), "server": server_name}), 500


# ============================================================

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)

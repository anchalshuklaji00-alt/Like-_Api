from telethon import TelegramClient
import json
import asyncio
import re

# --- CONFIGURATION ---
api_id = 34263972
api_hash = 'fd80c37158f3e65b444fa656e0313b18'
bot_username = '@FFPlayerInfoBot' 

client = TelegramClient('rolex_session', api_id, api_hash)

async def main():
    await client.start()
    print("👑 Rolex System: Bot se connect ho gaya!")

    # 1. SABSE PEHLE PURANE TOKENS SAAF KARO
    with open("tokens.json", "w") as f:
        json.dump([], f)
    print("🧹 tokens.json se purane expired tokens hata diye gaye hain...")

    # 2. UID/PASS FILE READ KARO
    try:
        with open("uidpass.json", "r") as f:
            accounts = json.load(f)
    except Exception as e:
        print(f"❌ Error: uidpass.json file nahi mili ya format galat hai! ({e})")
        return

    new_tokens = []

    # 3. HAR ACCOUNT KE LIYE TOKEN MANGO
    for acc in accounts:
        uid = acc.get("uid")
        password = acc.get("password")
        
        # Bot ko exactly "Token {uid} {pass}" bhejna hai
        command = f"Token {uid} {password}"
        print(f"\n📡 Requesting token for UID: {uid}...")
        await client.send_message(bot_username, command)
        
        print("⏳ Waiting for bot reply (7 seconds)...")
        await asyncio.sleep(7) # Bot ko reply design karne me time lagta hai
        
        # 4. BOT KA MESSAGE PADHO AUR TOKEN NIKALO
        messages = await client.get_messages(bot_username, limit=1)
        if not messages:
            print("❌ Bot ne koi reply nahi diya!")
            continue
            
        reply_text = messages[0].text
        
        # Regex to extract exactly the string starting with eyJ after "Token: "
        match = re.search(r'Token:\s*(eyJ[a-zA-Z0-9._-]+)', reply_text)
        
        if match:
            jwt_token = match.group(1)
            new_tokens.append({"token": jwt_token})
            print(f"✅ Success! Token extracted for {uid}.")
        else:
            print(f"❌ Token extraction failed! Bot ka reply format match nahi hua.")

    # 5. NAYE TOKENS FILE ME SAVE KARO
    if new_tokens:
        with open("tokens.json", "w") as f:
            json.dump(new_tokens, f, indent=4)
        print("\n✨ SYSTEM UPDATE: Saare naye tokens 'tokens.json' me save ho gaye!")
    else:
        print("\n⚠️ WARNING: Koi naya token save nahi hua.")

with client:
    client.loop.run_until_complete(main())

from telethon import TelegramClient
import json
import asyncio

# --- CONFIGURATION ---
api_id = 34263972
api_hash = 'fd80c37158f3e65b444fa656e0313b18'
bot_username = '@FFPlayerInfoBot' 

client = TelegramClient('rolex_session', api_id, api_hash)

async def main():
    await client.start()
    print("👑 Rolex System: Bot se connect ho gaya!")

    # 1. PURANE TOKENS SAAF KARO
    with open("tokens.json", "w") as f:
        json.dump([], f)
    print("🧹 Purane tokens clear kar diye gaye hain...")

    # 2. UID/PASS FILE READ KARO
    try:
        with open("uidpass.json", "r") as f:
            accounts = json.load(f)
    except Exception as e:
        print(f"❌ Error: uidpass.json file nahi mili! ({e})")
        return

    new_tokens = []

    # 3. HAR ACCOUNT KE LIYE TOKEN MANGO
    for acc in accounts:
        uid = acc.get("uid")
        password = acc.get("password")
        
        command = f"Token {uid} {password}"
        print(f"\n📡 Requesting token for UID: {uid}...")
        await client.send_message(bot_username, command)
        
        print("⏳ Waiting for bot reply (8 seconds)...")
        await asyncio.sleep(8) 
        
        # 4. BOT KA MESSAGE PADHO AUR LINE-BY-LINE CHECK KARO
        messages = await client.get_messages(bot_username, limit=5)
        
        token_found = False
        for msg in messages:
            if msg.text and 'eyJ' in msg.text:
                lines = msg.text.split('\n')
                for line in lines:
                    if 'Token:' in line and 'eyJ' in line:
                        # 👇 YAHAN FIX KIYA HAI: Extra stars ** aur backticks ` hata diye
                        jwt_token = line.split('Token:')[1].replace('*', '').replace('`', '').strip()
                        
                        # STRICT FORMAT: Sirf aur sirf "token" jayega
                        new_tokens.append({"token": jwt_token})
                        
                        print(f"✅ Success! Token extracted cleanly.")
                        token_found = True
                        break 
                
                if token_found:
                    break 
        
        if not token_found:
            print(f"❌ Token extraction failed for {uid}!")

    # 5. NAYE TOKENS STRICT FORMAT MEIN SAVE KARO
    if new_tokens:
        with open("tokens.json", "w") as f:
            json.dump(new_tokens, f, indent=2) 
        print("\n✨ SYSTEM UPDATE: Tokens exactly 'Token Only' format mein save ho gaye!")
    else:
        print("\n⚠️ WARNING: Koi naya token save nahi hua.")

with client:
    client.loop.run_until_complete(main())

# plugins/hashcrack.py

from telethon import events
from client import client
import hashlib
import aiohttp
import asyncio

@client.on(events.NewMessage(pattern=r"\.hash(?:\s+(md5|sha1|sha256|sha512)\s+(.+))?", outgoing=True))
async def hash_generator(event):
    match = event.pattern_match
    hash_type = match.group(1) if match else None
    text_input = match.group(2) if match else None
    reply = await event.get_reply_message()

    if not text_input and reply:
        text_input = reply.message.strip()
        if not hash_type:
            hash_type = "sha256"  # پیش‌فرض

    if not text_input:
        await event.reply("""
🔐 **Hash Generator & Cracker**
━━━━━━━━━━━━━━━━━━
**تولید Hash:**
`.hash md5 متن`
`.hash sha256 متن`
`.hash sha1 متن`
`.hash sha512 متن`

**شکستن Hash:**
`.crack hash_value`

**مثال:**
`.hash md5 password123`
`.crack 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8`
        """.strip())
        return

    await event.edit(f"🔄 در حال تولید {hash_type.upper()} hash...")

    try:
        # انتخاب الگوریتم hash
        if hash_type == "md5":
            hash_obj = hashlib.md5()
        elif hash_type == "sha1":
            hash_obj = hashlib.sha1()
        elif hash_type == "sha256":
            hash_obj = hashlib.sha256()
        elif hash_type == "sha512":
            hash_obj = hashlib.sha512()
        else:
            await event.edit("⚠️ نوع hash پشتیبانی نمی‌شود!")
            return

        hash_obj.update(text_input.encode('utf-8'))
        hash_result = hash_obj.hexdigest()

        msg = f"""
🔐 **Hash تولید شده**
━━━━━━━━━━━━━━━━━━
📝 **متن اصلی:** `{text_input}`
🔒 **نوع:** {hash_type.upper()}
🔑 **Hash:** `{hash_result}`
📏 **طول:** {len(hash_result)} کاراکتر
━━━━━━━━━━━━━━━━━━
        """.strip()

        await event.edit(msg)

    except Exception as e:
        await event.edit(f"⚠️ خطا: {e}")

@client.on(events.NewMessage(pattern=r"\.crack(?:\s+([a-fA-F0-9]+))?", outgoing=True))
async def hash_cracker(event):
    hash_input = event.pattern_match.group(1)
    reply = await event.get_reply_message()

    if not hash_input and reply:
        hash_input = reply.message.strip()

    if not hash_input:
        await event.reply("❌ لطفاً hash را وارد کن یا به پیامی حاوی hash ریپلای کن.")
        return

    await event.edit("🔍 در حال جستجوی hash در دیتابیس...")

    try:
        # تشخیص نوع hash بر اساس طول
        hash_length = len(hash_input)
        if hash_length == 32:
            hash_type = "MD5"
        elif hash_length == 40:
            hash_type = "SHA1"
        elif hash_length == 64:
            hash_type = "SHA256"
        elif hash_length == 128:
            hash_type = "SHA512"
        else:
            await event.edit("⚠️ نوع hash شناسایی نشد!")
            return

        # جستجو در چندین API
        apis = [
            f"https://md5decrypt.net/Api/api.php?hash={hash_input}&hash_type={hash_type.lower()}&email=deanna_abshire@proxymail.eu&code=1152464b80a61728",
            f"https://hashtoolkit.com/reverse-hash/?hash={hash_input}",
        ]

        result_found = False
        async with aiohttp.ClientSession() as session:
            for api_url in apis:
                try:
                    async with session.get(api_url, timeout=10) as resp:
                        if resp.status == 200:
                            data = await resp.text()
                            if data and data != "ERROR - HASH_NOT_FOUND" and len(data) < 100:
                                msg = f"""
🔓 **Hash شکسته شد!**
━━━━━━━━━━━━━━━━━━
🔑 **Hash:** `{hash_input}`
🔒 **نوع:** {hash_type}
📝 **متن اصلی:** `{data}`
━━━━━━━━━━━━━━━━━━
                                """.strip()
                                await event.edit(msg)
                                result_found = True
                                break
                except:
                    continue

        if not result_found:
            msg = f"""
❌ **Hash شکسته نشد**
━━━━━━━━━━━━━━━━━━
🔑 **Hash:** `{hash_input}`
🔒 **نوع:** {hash_type}
⚠️ **وضعیت:** در دیتابیس موجود نیست

💡 **پیشنهاد:** از رمزهای قوی‌تر استفاده کنید
━━━━━━━━━━━━━━━━━━
            """.strip()
            await event.edit(msg)

    except Exception as e:
        await event.edit(f"⚠️ خطا: {e}")

# plugins/ipinfo.py

from telethon import events
from client import client
import requests
import re

@client.on(events.NewMessage(pattern=r"\.ipinfo(?:\s+([\d\.]+))?", outgoing=True))
async def ip_info(event):
    ip_input = event.pattern_match.group(1)
    reply = await event.get_reply_message()

    # اگر آی‌پی به صورت ریپلای ارسال شده
    if not ip_input and reply:
        text = reply.message.strip()
        match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", text)
        if match:
            ip_input = match.group(1)

    if not ip_input:
        await event.reply("❌ لطفاً یک IP معتبر بده یا به پیامی حاوی IP ریپلای کن.")
        return

    url = f"http://ip-api.com/json/{ip_input}"
    try:
        res = requests.get(url, timeout=5)
        data = res.json()

        if data["status"] != "success":
            await event.reply(f"❌ خطا در دریافت اطلاعات: {data.get('message', 'نامشخص')}")
            return

        msg = f"""
🌐 **اطلاعات IP** `{data['query']}`
━━━━━━━━━━━━━━━━━━
🗺️ کشور: {data['country']}
🏙️ شهر: {data['city']}, {data['regionName']}
📮 کد پستی: {data['zip']}
📡 ISP: {data['isp']}
🏢 سازمان: {data['org']}
🛰️ AS: {data['as']}
📍 مختصات: {data['lat']}, {data['lon']}
🌏 منطقه زمانی: {data['timezone']}
━━━━━━━━━━━━━━━━━━
        """.strip()

        await event.reply(msg)
    except Exception as e:
        await event.reply(f"⚠️ خطا در اتصال: {e}")

# plugins/shorturl.py

from telethon import events
from client import client
import aiohttp
import re

@client.on(events.NewMessage(pattern=r"\.short(?:\s+(.+))?", outgoing=True))
async def url_shortener(event):
    url_input = event.pattern_match.group(1)
    reply = await event.get_reply_message()

    # اگر URL به صورت ریپلای ارسال شده
    if not url_input and reply:
        url_input = reply.message.strip()

    if not url_input:
        await event.reply("❌ لطفاً یک URL معتبر بده یا به پیامی حاوی URL ریپلای کن.")
        return

    # بررسی معتبر بودن URL
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    if not url_pattern.match(url_input):
        if not url_input.startswith(('http://', 'https://')):
            url_input = 'https://' + url_input
        if not url_pattern.match(url_input):
            await event.reply("❌ URL معتبر نیست!")
            return

    await event.edit("🔗 در حال کوتاه کردن URL...")

    try:
        # استفاده از is.gd API برای کوتاه کردن URL
        api_url = "https://is.gd/create.php"
        params = {
            'format': 'simple',
            'url': url_input
        }

        async with aiohttp.ClientSession() as session:
            async with session.get(api_url, params=params) as resp:
                if resp.status == 200:
                    short_url = await resp.text()
                    
                    if short_url.startswith('https://is.gd/'):
                        msg = f"""
🔗 **URL کوتاه شده**
━━━━━━━━━━━━━━━━━━
📎 **URL اصلی:**
`{url_input}`

✂️ **URL کوتاه:**
`{short_url}`

📊 **کاهش طول:** {len(url_input) - len(short_url)} کاراکتر
━━━━━━━━━━━━━━━━━━
                        """.strip()
                        await event.edit(msg)
                    else:
                        await event.edit(f"⚠️ خطا: {short_url}")
                else:
                    await event.edit("⚠️ خطا در کوتاه کردن URL!")

    except Exception as e:
        await event.edit(f"⚠️ خطا: {e}")

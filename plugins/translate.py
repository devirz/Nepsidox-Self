# plugins/translate.py

from telethon import events
from client import client
import aiohttp
import json

@client.on(events.NewMessage(pattern=r"\.tr(?:\s+(\w{2})\s+(.+))?", outgoing=True))
async def translate_text(event):
    match = event.pattern_match
    target_lang = match.group(1) if match else None
    text_input = match.group(2) if match else None
    reply = await event.get_reply_message()

    # اگر به پیامی ریپلای شده
    if not text_input and reply:
        text_input = reply.message.strip()
        if not target_lang:
            target_lang = "fa"  # پیش‌فرض فارسی

    if not text_input:
        await event.reply("""
📝 **راهنمای استفاده:**
`.tr en متن فارسی` - ترجمه به انگلیسی
`.tr fa English text` - ترجمه به فارسی
`.tr de متن` - ترجمه به آلمانی

یا به پیامی ریپلای کن: `.tr fa`
        """.strip())
        return

    if not target_lang:
        target_lang = "fa"

    await event.edit(f"🔄 در حال ترجمه به {target_lang.upper()}...")

    try:
        # استفاده از Google Translate API (رایگان)
        url = "https://translate.googleapis.com/translate_a/single"
        params = {
            'client': 'gtx',
            'sl': 'auto',
            'tl': target_lang,
            'dt': 't',
            'q': text_input
        }

        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    translated = data[0][0][0]
                    detected_lang = data[2] if len(data) > 2 else "نامشخص"
                    
                    msg = f"""
🌐 **ترجمه متن**
━━━━━━━━━━━━━━━━━━
📝 **متن اصلی** ({detected_lang}):
{text_input[:200]}{'...' if len(text_input) > 200 else ''}

🔄 **ترجمه شده** ({target_lang}):
{translated}
━━━━━━━━━━━━━━━━━━
                    """.strip()
                    
                    await event.edit(msg)
                else:
                    await event.edit("⚠️ خطا در دریافت ترجمه!")

    except Exception as e:
        await event.edit(f"⚠️ خطا در ترجمه: {e}")

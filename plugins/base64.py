# plugins/base64.py

from telethon import events
from client import client
import base64

@client.on(events.NewMessage(pattern=r"\.b64(?:\s+(encode|decode)\s+(.+))?", outgoing=True))
async def base64_handler(event):
    match = event.pattern_match
    operation = match.group(1) if match else None
    text_input = match.group(2) if match else None
    reply = await event.get_reply_message()

    # اگر به پیامی ریپلای شده
    if not text_input and reply:
        text_input = reply.message.strip()
        if not operation:
            # تشخیص خودکار نوع عملیات
            try:
                base64.b64decode(text_input, validate=True)
                operation = "decode"
            except:
                operation = "encode"

    if not text_input:
        await event.reply("""
🔐 **Base64 کدگذاری/رمزگشایی**
━━━━━━━━━━━━━━━━━━
**استفاده:**
`.b64 encode متن` - کدگذاری
`.b64 decode کد` - رمزگشایی
`.b64 متن` - تشخیص خودکار

یا به پیامی ریپلای کن: `.b64 encode`
        """.strip())
        return

    await event.edit(f"🔄 در حال {operation}...")

    try:
        if operation == "encode":
            # کدگذاری به Base64
            encoded_bytes = base64.b64encode(text_input.encode('utf-8'))
            result = encoded_bytes.decode('ascii')
            
            msg = f"""
🔐 **Base64 کدگذاری**
━━━━━━━━━━━━━━━━━━
📝 **متن اصلی:**
`{text_input[:100]}{'...' if len(text_input) > 100 else ''}`

🔒 **کد شده:**
`{result}`

📊 **طول:** {len(text_input)} → {len(result)} کاراکتر
━━━━━━━━━━━━━━━━━━
            """.strip()
            
        elif operation == "decode":
            # رمزگشایی از Base64
            try:
                decoded_bytes = base64.b64decode(text_input, validate=True)
                result = decoded_bytes.decode('utf-8')
                
                msg = f"""
🔓 **Base64 رمزگشایی**
━━━━━━━━━━━━━━━━━━
🔒 **کد اصلی:**
`{text_input[:100]}{'...' if len(text_input) > 100 else ''}`

📝 **رمزگشایی شده:**
`{result}`

📊 **طول:** {len(text_input)} → {len(result)} کاراکتر
━━━━━━━━━━━━━━━━━━
                """.strip()
                
            except Exception:
                await event.edit("⚠️ خطا: کد Base64 معتبر نیست!")
                return
        else:
            await event.edit("⚠️ عملیات نامعتبر! از encode یا decode استفاده کن.")
            return

        await event.edit(msg)

    except UnicodeDecodeError:
        await event.edit("⚠️ خطا: متن حاوی کاراکترهای غیرقابل رمزگشایی است!")
    except Exception as e:
        await event.edit(f"⚠️ خطا: {e}")

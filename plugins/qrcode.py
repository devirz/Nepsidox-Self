# plugins/qrcode.py

from telethon import events
from client import client
import qrcode
import io
from PIL import Image

@client.on(events.NewMessage(pattern=r"\.qr(?:\s+(.+))?", outgoing=True))
async def qr_generator(event):
    text_input = event.pattern_match.group(1)
    reply = await event.get_reply_message()

    # اگر متن به صورت ریپلای ارسال شده
    if not text_input and reply:
        text_input = reply.message.strip()

    if not text_input:
        await event.reply("❌ لطفاً متنی برای تولید QR Code بده یا به پیامی ریپلای کن.")
        return

    await event.edit("🔄 در حال تولید QR Code...")

    try:
        # تولید QR Code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(text_input)
        qr.make(fit=True)

        # ایجاد تصویر
        img = qr.make_image(fill_color="black", back_color="white")
        
        # تبدیل به bytes
        image_stream = io.BytesIO()
        image_stream.name = 'qrcode.png'
        img.save(image_stream, 'PNG')
        image_stream.seek(0)

        # ارسال تصویر
        await event.client.send_file(
            event.chat_id,
            image_stream,
            caption=f"📱 **QR Code برای:**\n`{text_input[:100]}{'...' if len(text_input) > 100 else ''}`",
            reply_to=event.message
        )
        await event.delete()

    except Exception as e:
        await event.edit(f"⚠️ خطا در تولید QR Code: {e}")

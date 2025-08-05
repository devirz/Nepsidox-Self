# plugins/steganography.py

from telethon import events
from client import client
from PIL import Image
import io
import base64

@client.on(events.NewMessage(pattern=r"\.stego(?:\s+(hide|extract|process))?", outgoing=True))
async def steganography_handler(event):
    operation = event.pattern_match.group(1)
    reply = await event.get_reply_message()

    if not operation:
        await event.reply("""
🖼️ **Steganography - مخفی‌سازی در تصاویر**
━━━━━━━━━━━━━━━━━━
**مخفی کردن متن:**
1. `.stego hide متن مورد نظر`
2. تصویر PNG را ارسال کن
3. روی تصویر ریپلای کن: `.stego process`

**استخراج متن:**
1. روی تصویر حاوی متن مخفی ریپلای کن
2. دستور بده: `.stego extract`

**مثال:**
`.stego hide سلام دنیا`
`.stego process` (روی تصویر)
`.stego extract` (روی تصویر مخفی)

**نکات:**
• فقط تصاویر PNG پشتیبانی می‌شود
• متن به صورت مخفی در پیکسل‌ها ذخیره می‌شود
        """.strip())
        return

    if operation == "hide":
        if not reply or not reply.message:
            await event.edit("❌ ابتدا متن مورد نظر را بنویس و روی آن ریپلای کن!")
            return
        
        await event.edit("📤 حالا تصویر PNG را ارسال کن...")
        
        # ذخیره متن برای استفاده بعدی
        event.client._stego_text = reply.message
        return

    elif operation == "extract":
        if not reply or not reply.media:
            await event.edit("❌ روی تصویری که حاوی متن مخفی است ریپلای کن!")
            return

        await event.edit("🔍 در حال استخراج متن مخفی...")

        try:
            # دانلود تصویر
            image_bytes = await reply.download_media(bytes)
            image = Image.open(io.BytesIO(image_bytes))
            
            if image.format != 'PNG':
                await event.edit("⚠️ فقط تصاویر PNG پشتیبانی می‌شود!")
                return

            # استخراج متن مخفی
            hidden_text = extract_text_from_image(image)
            
            if hidden_text:
                msg = f"""
🔓 **متن مخفی استخراج شد**
━━━━━━━━━━━━━━━━━━
📝 **متن:** 
`{hidden_text}`

📊 **طول:** {len(hidden_text)} کاراکتر
━━━━━━━━━━━━━━━━━━
                """.strip()
                await event.edit(msg)
            else:
                await event.edit("❌ هیچ متن مخفی در این تصویر یافت نشد!")

        except Exception as e:
            await event.edit(f"⚠️ خطا در استخراج: {e}")

@client.on(events.NewMessage(pattern=r"\.stego\s+hide\s+(.+)", outgoing=True))
async def hide_text_in_next_image(event):
    text_to_hide = event.pattern_match.group(1)
    
    # ذخیره متن برای استفاده بعدی
    event.client._stego_text = text_to_hide
    await event.edit("📤 متن ذخیره شد. حالا تصویر PNG را ارسال کن و روی آن `.stego process` بزن")

@client.on(events.NewMessage(pattern=r"\.stego\s+process", outgoing=True))
async def process_image_for_hiding(event):
    reply = await event.get_reply_message()
    
    if not reply or not reply.media:
        await event.edit("❌ روی تصویری که می‌خواهی متن در آن مخفی کنی ریپلای کن!")
        return
        
    if not hasattr(event.client, '_stego_text'):
        await event.edit("❌ ابتدا متن را با `.stego hide متن` ذخیره کن!")
        return

    await event.edit("🔄 در حال مخفی کردن متن در تصویر...")

    try:
        # دانلود تصویر
        image_bytes = await reply.download_media(bytes)
        image = Image.open(io.BytesIO(image_bytes))
        
        # تبدیل به PNG اگر نیست
        if image.format != 'PNG':
            image = image.convert('RGBA')
        
        # مخفی کردن متن
        text_to_hide = event.client._stego_text
        stego_image = hide_text_in_image(image, text_to_hide)
        
        # ذخیره تصویر
        output = io.BytesIO()
        output.name = 'hidden_message.png'
        stego_image.save(output, 'PNG')
        output.seek(0)
        
        # ارسال تصویر به صورت فایل غیرفشرده
        await event.client.send_file(
            event.chat_id,
            output,
            caption=f"🔒 **متن با موفقیت در تصویر مخفی شد!**\n\n📝 متن مخفی: `{text_to_hide[:50]}{'...' if len(text_to_hide) > 50 else ''}`",
            reply_to=event.message,
            force_document=True,
            allow_cache=False,
            supports_streaming=False
        )
        
        # پاک کردن متن ذخیره شده
        del event.client._stego_text
        await event.delete()
        
    except Exception as e:
        await event.edit(f"⚠️ خطا در مخفی‌سازی: {e}")
        if hasattr(event.client, '_stego_text'):
            del event.client._stego_text

def hide_text_in_image(image, text):
    """مخفی کردن متن در LSB پیکسل‌های تصویر"""
    # تبدیل متن به باینری
    binary_text = ''.join(format(ord(char), '08b') for char in text)
    binary_text += '1111111111111110'  # delimiter
    
    pixels = list(image.getdata())
    new_pixels = []
    
    text_index = 0
    for pixel in pixels:
        if text_index < len(binary_text):
            # تغییر LSB کانال قرمز
            r, g, b = pixel[:3]
            r = (r & 0xFE) | int(binary_text[text_index])
            new_pixels.append((r, g, b) + pixel[3:])
            text_index += 1
        else:
            new_pixels.append(pixel)
    
    new_image = Image.new(image.mode, image.size)
    new_image.putdata(new_pixels)
    return new_image

def extract_text_from_image(image):
    """استخراج متن مخفی از LSB پیکسل‌های تصویر"""
    pixels = list(image.getdata())
    binary_text = ''
    
    for pixel in pixels:
        r = pixel[0]
        binary_text += str(r & 1)
    
    # جستجوی delimiter
    delimiter = '1111111111111110'
    end_index = binary_text.find(delimiter)
    
    if end_index == -1:
        return None
    
    binary_text = binary_text[:end_index]
    
    # تبدیل باینری به متن
    text = ''
    for i in range(0, len(binary_text), 8):
        byte = binary_text[i:i+8]
        if len(byte) == 8:
            text += chr(int(byte, 2))
    
    return text if text else None

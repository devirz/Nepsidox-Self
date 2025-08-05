# plugins/cryptoanalyzer.py

from telethon import events
from client import client
import re
import base64
import binascii
import hashlib
import string
from collections import Counter
import asyncio

@client.on(events.NewMessage(pattern=r"\.crypto(?:\s+(.+))?", outgoing=True))
async def crypto_analyzer(event):
    text_input = event.pattern_match.group(1)
    reply = await event.get_reply_message()

    if not text_input and reply:
        text_input = reply.message.strip()

    if not text_input:
        await event.reply("""
🔐 **Crypto Analyzer - تحلیلگر رمزنگاری**
━━━━━━━━━━━━━━━━━━
**قابلیت‌ها:**
• تشخیص نوع رمزگذاری
• تحلیل فرکانس کاراکترها
• شکستن Caesar Cipher
• تشخیص Base64, Hex, Binary
• تحلیل آماری متن
• شناسایی الگوهای رمزی

**استفاده:**
`.crypto متن_رمزی`
`.crypto SGVsbG8gV29ybGQ=`
`.crypto 48656c6c6f20576f726c64`

**مثال:**
`.crypto Khoor Zruog` - Caesar cipher
        """.strip())
        return

    await event.edit("🔍 در حال تحلیل رمزنگاری...")

    try:
        analysis_results = []
        
        # 1. تشخیص Base64
        if is_base64(text_input):
            try:
                decoded = base64.b64decode(text_input).decode('utf-8')
                analysis_results.append(f"🔓 **Base64:** `{decoded}`")
            except:
                pass

        # 2. تشخیص Hex
        if is_hex(text_input):
            try:
                decoded = bytes.fromhex(text_input.replace(' ', '')).decode('utf-8')
                analysis_results.append(f"🔓 **Hex:** `{decoded}`")
            except:
                pass

        # 3. تشخیص Binary
        if is_binary(text_input):
            try:
                binary_clean = text_input.replace(' ', '')
                decoded = ''.join(chr(int(binary_clean[i:i+8], 2)) for i in range(0, len(binary_clean), 8))
                analysis_results.append(f"🔓 **Binary:** `{decoded}`")
            except:
                pass

        # 4. تحلیل Caesar Cipher
        caesar_results = analyze_caesar(text_input)
        if caesar_results:
            analysis_results.extend(caesar_results[:3])  # نمایش 3 نتیجه برتر

        # 5. تحلیل فرکانس
        freq_analysis = frequency_analysis(text_input)
        
        # 6. تشخیص الگوهای خاص
        patterns = detect_patterns(text_input)

        # 7. تحلیل آماری
        stats = text_statistics(text_input)

        # ساخت گزارش نهایی
        if analysis_results:
            decoded_text = "\n".join(analysis_results)
        else:
            decoded_text = "❌ هیچ رمزگذاری شناخته شده یافت نشد"

        msg = f"""
🔐 **نتایج تحلیل رمزنگاری**
━━━━━━━━━━━━━━━━━━
📝 **متن اصلی:** `{text_input[:50]}{'...' if len(text_input) > 50 else ''}`

**🔓 رمزگشایی:**
{decoded_text}

**📊 آمار متن:**
• طول: {stats['length']} کاراکتر
• کلمات: {stats['words']}
• حروف: {stats['letters']}
• اعداد: {stats['digits']}
• نمادها: {stats['symbols']}

**🔍 الگوهای شناسایی شده:**
{patterns}

**📈 فرکانس حروف:**
{freq_analysis}
━━━━━━━━━━━━━━━━━━
        """.strip()

        await event.edit(msg)

    except Exception as e:
        await event.edit(f"⚠️ خطا در تحلیل: {e}")

def is_base64(text):
    """بررسی اینکه آیا متن Base64 است"""
    try:
        if len(text) % 4 == 0 and re.match(r'^[A-Za-z0-9+/]*={0,2}$', text):
            base64.b64decode(text, validate=True)
            return True
    except:
        pass
    return False

def is_hex(text):
    """بررسی اینکه آیا متن Hex است"""
    hex_text = text.replace(' ', '').replace('0x', '')
    return len(hex_text) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in hex_text)

def is_binary(text):
    """بررسی اینکه آیا متن Binary است"""
    binary_text = text.replace(' ', '')
    return len(binary_text) % 8 == 0 and all(c in '01' for c in binary_text)

def analyze_caesar(text):
    """تحلیل Caesar Cipher"""
    results = []
    if not text.replace(' ', '').isalpha():
        return results
    
    for shift in range(1, 26):
        decoded = caesar_decrypt(text, shift)
        # بررسی اینکه آیا نتیجه معنادار است
        if is_meaningful_text(decoded):
            results.append(f"🔓 **Caesar {shift}:** `{decoded}`")
    
    return results

def caesar_decrypt(text, shift):
    """رمزگشایی Caesar Cipher"""
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            result += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
        else:
            result += char
    return result

def is_meaningful_text(text):
    """بررسی اینکه آیا متن معنادار است"""
    # بررسی فرکانس حروف انگلیسی
    common_letters = 'etaoinshrdlu'
    text_lower = text.lower().replace(' ', '')
    if len(text_lower) < 3:
        return False
    
    common_count = sum(1 for char in text_lower[:10] if char in common_letters)
    return common_count >= len(text_lower[:10]) * 0.4

def frequency_analysis(text):
    """تحلیل فرکانس کاراکترها"""
    letters_only = ''.join(c.lower() for c in text if c.isalpha())
    if not letters_only:
        return "هیچ حرفی یافت نشد"
    
    freq = Counter(letters_only)
    top_5 = freq.most_common(5)
    return ' | '.join(f"{char}: {count}" for char, count in top_5)

def detect_patterns(text):
    """تشخیص الگوهای خاص در متن"""
    patterns = []
    
    # الگوهای مختلف
    if re.search(r'[A-Z]{2,}', text):
        patterns.append("حروف بزرگ متوالی")
    if re.search(r'\d{4,}', text):
        patterns.append("اعداد طولانی")
    if re.search(r'[!@#$%^&*()]{2,}', text):
        patterns.append("نمادهای متوالی")
    if len(set(text)) < len(text) * 0.5:
        patterns.append("تکرار زیاد کاراکترها")
    
    return " | ".join(patterns) if patterns else "الگوی خاصی یافت نشد"

def text_statistics(text):
    """آمار کلی متن"""
    return {
        'length': len(text),
        'words': len(text.split()),
        'letters': sum(1 for c in text if c.isalpha()),
        'digits': sum(1 for c in text if c.isdigit()),
        'symbols': sum(1 for c in text if not c.isalnum() and not c.isspace())
    }

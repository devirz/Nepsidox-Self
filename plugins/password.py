# plugins/password.py

from telethon import events
from client import client
import random
import string

@client.on(events.NewMessage(pattern=r"\.pass(?:\s+(\d+))?", outgoing=True))
async def password_generator(event):
    length_str = event.pattern_match.group(1)
    
    # طول پیش‌فرض 12 کاراکتر
    length = 12
    if length_str:
        try:
            length = int(length_str)
            if length < 4:
                length = 4
            elif length > 128:
                length = 128
        except ValueError:
            length = 12

    await event.edit("🔐 در حال تولید رمز عبور...")

    try:
        # تعریف مجموعه کاراکترها
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # اطمینان از وجود حداقل یک کاراکتر از هر نوع
        password = [
            random.choice(lowercase),
            random.choice(uppercase),
            random.choice(digits),
            random.choice(symbols)
        ]
        
        # تکمیل باقی کاراکترها
        all_chars = lowercase + uppercase + digits + symbols
        for _ in range(length - 4):
            password.append(random.choice(all_chars))
        
        # مخلوط کردن کاراکترها
        random.shuffle(password)
        final_password = ''.join(password)
        
        # محاسبه قدرت رمز عبور
        strength = "ضعیف"
        if length >= 8:
            strength = "متوسط"
        if length >= 12:
            strength = "قوی"
        if length >= 16:
            strength = "بسیار قوی"

        msg = f"""
🔐 **رمز عبور تولید شده**
━━━━━━━━━━━━━━━━━━
🔑 **رمز عبور:** `{final_password}`
📏 **طول:** {length} کاراکتر
💪 **قدرت:** {strength}

⚠️ **نکات امنیتی:**
• این پیام را پس از کپی کردن پاک کنید
• رمز عبور را در جای امن نگهداری کنید
• از رمزهای تکراری استفاده نکنید
━━━━━━━━━━━━━━━━━━
        """.strip()
        
        await event.edit(msg)

    except Exception as e:
        await event.edit(f"⚠️ خطا در تولید رمز عبور: {e}")

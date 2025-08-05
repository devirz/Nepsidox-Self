# plugins/help.py

from telethon import events
from client import client
import asyncio

@client.on(events.NewMessage(pattern=r"\.help(?:\s+(.+))?", outgoing=True))
async def help_command(event):
    category = event.pattern_match.group(1)
    
    if not category:
        await event.edit("""
🤖 **راهنمای کامل Nepsidox Selfbot**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**دسته‌بندی دستورات:**
`.help security` - ابزارهای امنیت و تست نفوذ
`.help network` - ابزارهای شبکه و اطلاعات
`.help crypto` - ابزارهای رمزنگاری و هش
`.help utility` - ابزارهای کاربردی
`.help media` - ابزارهای رسانه‌ای
`.help system` - ابزارهای سیستمی
`.help all` - نمایش همه دستورات

**دستورات سریع:**
• `.help security` - ابزارهای هکینگ و تست نفوذ
• `.help network` - اسکن شبکه و اطلاعات IP
• `.help crypto` - رمزنگاری و تحلیل هش

**نکات مهم:**
⚠️ همه ابزارهای امنیتی فقط برای تست سیستم‌های خودتان
🔒 از ابزارهای رمزنگاری برای حفظ حریم خصوصی استفاده کنید
📚 برای اطلاعات بیشتر از `.help [category]` استفاده کنید

💡 **مثال:** `.help security` برای مشاهده ابزارهای امنیتی
        """.strip())
        return
    
    if category.lower() == "security":
        await event.edit("""
🛡️ **ابزارهای امنیت و تست نفوذ**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**🔴 تست آسیب‌پذیری:**
`.sqli <url>` - تست SQL Injection پیشرفته
**مثال:** `.sqli https://example.com/page.php?id=1`
• تست 20+ payload مختلف
• استخراج نام دیتابیس و جداول
• تشخیص نوع آسیب‌پذیری

`.xss <url>` - اسکنر XSS حرفه‌ای
**مثال:** `.xss https://target.com/search.php?q=test`
• تست Reflected و DOM-based XSS
• تحلیل context قرارگیری
• ارزیابی شدت آسیب‌پذیری

`.dirtraversal <url>` - تست Directory Traversal
**مثال:** `.dirtraversal https://site.com/page.php?file=doc.pdf`
• 40+ payload برای Unix/Windows
• تشخیص فایل‌های حساس
• سیستم امتیازدهی اطمینان

`.vulnscan <url>` - ارزیابی جامع آسیب‌پذیری
**مثال:** `.vulnscan https://example.com`
• تست چندین نوع آسیب‌پذیری
• بررسی security headers
• امتیازدهی ریسک

**🔍 اسکن شبکه:**
`.portscan <host> [type]` - اسکن پورت پیشرفته
**مثال:** `.portscan example.com web`
**انواع:** common, web, database, remote, mail, full
• تشخیص سرویس با banner grabbing
• تحلیل SSL certificate
• توصیه‌های امنیتی

`.subdomain <domain>` - کشف Subdomain
**مثال:** `.subdomain example.com`
• جستجوی Certificate Transparency
• DNS bruteforce با 70+ wordlist
• تحلیل SSL و HTTP headers

⚠️ **هشدار:** فقط برای تست سیستم‌های خودتان استفاده کنید!
        """.strip())
        
    elif category.lower() == "network":
        await event.edit("""
🌐 **ابزارهای شبکه و اطلاعات**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**📡 اطلاعات شبکه:**
`.ipinfo <ip>` - اطلاعات کامل IP
**مثال:** `.ipinfo 8.8.8.8`
• مکان جغرافیایی
• اطلاعات ISP و سازمان
• وضعیت امنیتی

`.whois <domain>` - اطلاعات دامنه
**مثال:** `.whois google.com`
• اطلاعات ثبت دامنه
• DNS records
• تاریخ انقضا

`.ping <host>` - تست اتصال
**مثال:** `.ping google.com`
• زمان پاسخ
• packet loss
• آمار اتصال

**🔍 اسکن و تحلیل:**
`.portscanner <ip> <port>` - اسکن پورت ساده
**مثال:** `.portscanner 192.168.1.1 80`
• بررسی وضعیت پورت
• تشخیص سرویس

**🌍 اطلاعات عمومی:**
`.weather <city>` - آب و هوا
**مثال:** `.weather Tehran`
• دمای فعلی و پیش‌بینی
• رطوبت و فشار هوا
• سرعت باد

💡 **نکته:** برای اطلاعات دقیق‌تر از IP و دامنه‌های معتبر استفاده کنید
        """.strip())
        
    elif category.lower() == "crypto":
        await event.edit("""
🔐 **ابزارهای رمزنگاری و هش**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**🔑 رمزنگاری:**
`.cryptoanalyzer <text>` - تحلیل رمزنگاری
**مثال:** `.cryptoanalyzer SGVsbG8gV29ybGQ=`
• تشخیص نوع رمزنگاری
• رمزگشایی خودکار
• پشتیبانی از Base64, Hex, ROT13

`.base64 <text>` - رمزنگاری Base64
**مثال:** `.base64 Hello World`
• رمزنگاری و رمزگشایی
• تشخیص خودکار نوع

**🔨 شکستن رمز:**
`.hashcrack <hash>` - شکستن هش
**مثال:** `.hashcrack 5d41402abc4b2a76b9719d911017c592`
• پشتیبانی از MD5, SHA1, SHA256
• استفاده از wordlist
• تشخیص نوع هش

**🔐 تولید رمز:**
`.password [length]` - تولید رمز قوی
**مثال:** `.password 16`
• رمزهای تصادفی امن
• ترکیب حروف، اعداد و نمادها
• طول قابل تنظیم

**🖼️ مخفی‌سازی:**
`.steganography <image>` - مخفی‌سازی در تصویر
**استفاده:** پاسخ به تصویر + دستور
• مخفی کردن متن در تصویر
• استخراج متن مخفی
• حفظ کیفیت تصویر

💡 **نکته:** همه ابزارهای رمزنگاری برای حفظ حریم خصوصی طراحی شده‌اند
        """.strip())
        
    elif category.lower() == "utility":
        await event.edit("""
🛠️ **ابزارهای کاربردی**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**🔗 لینک و URL:**
`.shorturl <url>` - کوتاه کردن لینک
**مثال:** `.shorturl https://www.google.com`
• ایجاد لینک کوتاه
• آمار کلیک
• مدیریت لینک‌ها

**📱 QR Code:**
`.qrcode <text>` - تولید QR Code
**مثال:** `.qrcode https://telegram.org`
• تبدیل متن به QR Code
• پشتیبانی از URL، متن، شماره تلفن
• کیفیت بالا

**🔤 ترجمه:**
`.translate <text>` - ترجمه متن
**مثال:** `.translate Hello World`
• ترجمه خودکار به فارسی
• تشخیص زبان مبدا
• پشتیبانی از زبان‌های مختلف

**🧮 محاسبات:**
`.calc <expression>` - ماشین حساب
**مثال:** `.calc 2+2*3`
• محاسبات ریاضی پیشرفته
• توابع مثلثاتی
• محاسبات علمی

**⏰ زمان:**
`.timesticker` - برچسب زمان
• نمایش زمان فعلی
• تبدیل منطقه زمانی
• فرمت‌های مختلف

**💻 اجرای کد:**
`.exec <code>` - اجرای کد Python
**مثال:** `.exec print("Hello")`
• اجرای کد Python
• نمایش خروجی
• محیط امن

⚠️ **هشدار:** در اجرای کد احتیاط کنید و از کدهای مخرب استفاده نکنید
        """.strip())
        
    elif category.lower() == "media":
        await event.edit("""
🎬 **ابزارهای رسانه‌ای**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**📹 دانلود ویدیو:**
`.ytdl <url>` - دانلود از یوتیوب
**مثال:** `.ytdl https://youtube.com/watch?v=VIDEO_ID`
• دانلود ویدیو و صدا
• انتخاب کیفیت
• پشتیبانی از پلتفرم‌های مختلف

**🖼️ پردازش تصویر:**
`.steganography` - مخفی‌سازی در تصویر
**استفاده:** پاسخ به تصویر + دستور
• مخفی کردن متن در تصویر
• استخراج متن مخفی از تصویر
• حفظ کیفیت اصلی

**📱 QR Code:**
`.qrcode <text>` - تولید کد QR
**مثال:** `.qrcode متن مورد نظر`
• تبدیل متن به تصویر QR
• پشتیبانی از متن فارسی
• کیفیت بالا و قابل اسکن

**🔗 مدیریت لینک:**
`.shorturl <url>` - کوتاه‌سازی لینک
**مثال:** `.shorturl https://example.com/very/long/url`
• ایجاد لینک کوتاه
• ردیابی کلیک‌ها
• مدیریت لینک‌ها

💡 **نکته:** برای دانلود محتوا از قوانین کپی‌رایت پیروی کنید
        """.strip())
        
    elif category.lower() == "system":
        await event.edit("""
💻 **ابزارهای سیستمی**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**📊 مانیتورینگ سیستم:**
`.sysmonitoring` - نظارت بر سیستم
• استفاده CPU و RAM
• فضای دیسک
• پردازه‌های فعال
• دمای سیستم

**👻 حالت مخفی:**
`.ghostmode` - فعال/غیرفعال کردن حالت مخفی
• مخفی کردن آنلاین بودن
• عدم نمایش "در حال تایپ"
• حفظ حریم خصوصی

**💻 اجرای کد:**
`.exec <code>` - اجرای کد Python
**مثال:** `.exec import os; print(os.getcwd())`
• اجرای کد Python در محیط امن
• دسترسی به کتابخانه‌های استاندارد
• نمایش خروجی و خطاها

**🌐 وب شل:**
`.webshell` - ایجاد وب شل
• دسترسی راه دور به سیستم
• اجرای دستورات سیستمی
• مدیریت فایل‌ها

**⚠️ هشدارهای امنیتی:**
• از دستورات سیستمی با احتیاط استفاده کنید
• webshell فقط برای سیستم‌های خودتان
• exec را با کدهای امن اجرا کنید
• ghostmode ممکن است برخی قابلیت‌ها را محدود کند

💡 **نکته:** این ابزارها برای مدیریت و کنترل سیستم طراحی شده‌اند
        """.strip())
        
    elif category.lower() == "all":
        await event.edit("""
📚 **فهرست کامل دستورات Nepsidox**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**🛡️ امنیت و تست نفوذ:**
`.sqli` - تست SQL Injection
`.xss` - اسکنر XSS
`.dirtraversal` - تست Directory Traversal  
`.vulnscan` - ارزیابی آسیب‌پذیری
`.portscan` - اسکن پورت پیشرفته
`.subdomain` - کشف Subdomain

**🌐 شبکه و اطلاعات:**
`.ipinfo` - اطلاعات IP
`.whois` - اطلاعات دامنه
`.ping` - تست اتصال
`.portscanner` - اسکن پورت ساده

**🔐 رمزنگاری:**
`.cryptoanalyzer` - تحلیل رمز
`.base64` - رمزنگاری Base64
`.hashcrack` - شکستن هش
`.password` - تولید رمز
`.steganography` - مخفی‌سازی

**🛠️ ابزارهای کاربردی:**
`.shorturl` - کوتاه کردن لینک
`.qrcode` - تولید QR Code
`.translate` - ترجمه
`.calc` - ماشین حساب
`.timesticker` - برچسب زمان

**🎬 رسانه:**
`.ytdl` - دانلود ویدیو

**💻 سیستم:**
`.sysmonitoring` - نظارت سیستم
`.ghostmode` - حالت مخفی
`.exec` - اجرای کد
`.webshell` - وب شل

**📖 راهنما:**
`.help [category]` - راهنمای دسته‌بندی شده

💡 برای جزئیات هر دسته: `.help security`, `.help network`, etc.
        """.strip())
        
    else:
        await event.edit(f"""
❌ **دسته‌بندی نامعتبر: {category}**

**دسته‌بندی‌های معتبر:**
• `security` - ابزارهای امنیت و تست نفوذ
• `network` - ابزارهای شبکه
• `crypto` - ابزارهای رمزنگاری
• `utility` - ابزارهای کاربردی
• `media` - ابزارهای رسانه‌ای
• `system` - ابزارهای سیستمی
• `all` - همه دستورات

**مثال:** `.help security`
        """.strip())

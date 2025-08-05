# plugins/portscanner.py

from telethon import events
from client import client
import socket
import asyncio
import re
from datetime import datetime

@client.on(events.NewMessage(pattern=r"\.scan(?:\s+([^\s]+)(?:\s+(\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*)))?", outgoing=True))
async def port_scanner(event):
    match = event.pattern_match
    target = match.group(1) if match else None
    ports_input = match.group(2) if match else "21,22,23,25,53,80,110,443,993,995,8080,8443"
    
    reply = await event.get_reply_message()
    if not target and reply:
        target = reply.message.strip()

    if not target:
        await event.reply("""
🔍 **Port Scanner حرفه‌ای**
━━━━━━━━━━━━━━━━━━
**استفاده:**
`.scan domain.com` - اسکن پورت‌های معمول
`.scan 192.168.1.1 80,443,22` - اسکن پورت‌های خاص
`.scan example.com 1-1000` - اسکن محدوده پورت
`.scan target.com 80,443,1-100` - ترکیبی

**مثال‌ها:**
`.scan google.com`
`.scan 8.8.8.8 53,80,443`
`.scan localhost 3000-3010`
        """.strip())
        return

    await event.edit(f"🔍 در حال اسکن {target}...")

    try:
        # پارس کردن پورت‌ها
        ports = []
        for port_part in ports_input.split(','):
            port_part = port_part.strip()
            if '-' in port_part:
                start, end = map(int, port_part.split('-'))
                ports.extend(range(start, min(end + 1, 65536)))
            else:
                port = int(port_part)
                if 1 <= port <= 65535:
                    ports.append(port)

        if len(ports) > 1000:
            await event.edit("⚠️ تعداد پورت‌ها زیاد است! حداکثر 1000 پورت مجاز است.")
            return

        # تبدیل hostname به IP
        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            await event.edit(f"⚠️ نمی‌توان {target} را resolve کرد!")
            return

        await event.edit(f"🔍 اسکن {len(ports)} پورت در {target} ({target_ip})...")

        # اسکن پورت‌ها
        open_ports = []
        closed_ports = []
        
        async def scan_port(port):
            try:
                future = asyncio.open_connection(target_ip, port)
                reader, writer = await asyncio.wait_for(future, timeout=3)
                writer.close()
                await writer.wait_closed()
                return port, True
            except:
                return port, False

        # اجرای همزمان اسکن‌ها (با محدودیت)
        semaphore = asyncio.Semaphore(50)  # حداکثر 50 اتصال همزمان
        
        async def scan_with_semaphore(port):
            async with semaphore:
                return await scan_port(port)

        tasks = [scan_with_semaphore(port) for port in ports[:100]]  # محدود به 100 پورت
        results = await asyncio.gather(*tasks)

        for port, is_open in results:
            if is_open:
                open_ports.append(port)
            else:
                closed_ports.append(port)

        # تشخیص سرویس‌ها
        common_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 3389: "RDP", 5432: "PostgreSQL", 3306: "MySQL",
            6379: "Redis", 27017: "MongoDB", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
        }

        # ساخت گزارش
        scan_time = datetime.now().strftime("%H:%M:%S")
        
        if open_ports:
            services_info = []
            for port in sorted(open_ports):
                service = common_services.get(port, "Unknown")
                services_info.append(f"  🟢 {port} - {service}")
            
            services_text = "\n".join(services_info[:20])  # نمایش حداکثر 20 پورت
            if len(open_ports) > 20:
                services_text += f"\n  ... و {len(open_ports) - 20} پورت دیگر"
        else:
            services_text = "  ❌ هیچ پورت بازی یافت نشد"

        msg = f"""
🔍 **نتایج Port Scanner**
━━━━━━━━━━━━━━━━━━
🎯 **هدف:** {target} ({target_ip})
⏰ **زمان:** {scan_time}
📊 **اسکن شده:** {len(ports)} پورت
🟢 **باز:** {len(open_ports)} پورت
🔴 **بسته:** {len(closed_ports)} پورت

**پورت‌های باز:**
{services_text}
━━━━━━━━━━━━━━━━━━
        """.strip()

        await event.edit(msg)

    except ValueError:
        await event.edit("⚠️ فرمت پورت نامعتبر!")
    except Exception as e:
        await event.edit(f"⚠️ خطا در اسکن: {e}")

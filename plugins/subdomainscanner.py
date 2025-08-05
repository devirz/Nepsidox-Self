# plugins/subdomainscanner.py

from telethon import events
from client import client
import aiohttp
import asyncio
import socket
import ssl
import json
from typing import List, Dict, Optional, Set
import re

class SubdomainScanner:
    def __init__(self):
        self.found_subdomains = set()
        self.wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mx', 'test', 'dev',
            'staging', 'admin', 'api', 'blog', 'forum', 'shop', 'store', 'mobile',
            'app', 'cdn', 'static', 'img', 'images', 'css', 'js', 'assets',
            'help', 'support', 'docs', 'wiki', 'news', 'portal', 'secure', 'ssl',
            'vpn', 'remote', 'demo', 'beta', 'alpha', 'old', 'new', 'backup',
            'db', 'database', 'mysql', 'sql', 'phpmyadmin', 'adminer', 'redis',
            'git', 'svn', 'jenkins', 'ci', 'build', 'deploy', 'docker', 'k8s',
            'monitoring', 'logs', 'status', 'health', 'metrics', 'grafana',
            'kibana', 'elastic', 'search', 'solr', 'ldap', 'ad', 'sso',
            'auth', 'login', 'register', 'signup', 'account', 'profile',
            'dashboard', 'panel', 'control', 'manage', 'config', 'settings'
        ]
        self.session = None
        
    async def dns_lookup(self, subdomain: str, domain: str) -> Optional[Dict]:
        """DNS lookup برای subdomain"""
        full_domain = f"{subdomain}.{domain}"
        
        try:
            # DNS resolution
            loop = asyncio.get_event_loop()
            ip_addresses = await loop.run_in_executor(
                None, socket.gethostbyname_ex, full_domain
            )
            
            return {
                'subdomain': full_domain,
                'ips': ip_addresses[2],
                'canonical': ip_addresses[0],
                'status': 'resolved'
            }
            
        except socket.gaierror:
            return None
        except Exception:
            return None
    
    async def http_check(self, subdomain: str) -> Optional[Dict]:
        """بررسی HTTP/HTTPS برای subdomain"""
        results = {}
        
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{subdomain}"
                
                async with self.session.get(
                    url, 
                    timeout=aiohttp.ClientTimeout(total=5),
                    allow_redirects=False
                ) as resp:
                    
                    # دریافت اطلاعات پاسخ
                    headers = dict(resp.headers)
                    
                    results[protocol] = {
                        'status_code': resp.status,
                        'server': headers.get('Server', 'Unknown'),
                        'title': await self._extract_title(resp),
                        'redirect': headers.get('Location'),
                        'ssl_info': await self._get_ssl_info(subdomain) if protocol == 'https' else None
                    }
                    
            except asyncio.TimeoutError:
                results[protocol] = {'status': 'timeout'}
            except Exception as e:
                results[protocol] = {'status': 'error', 'error': str(e)}
        
        return results if any(r.get('status_code') for r in results.values()) else None
    
    async def _extract_title(self, response) -> Optional[str]:
        """استخراج title از HTML"""
        try:
            content = await response.text()
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
            return title_match.group(1).strip() if title_match else None
        except:
            return None
    
    async def _get_ssl_info(self, hostname: str) -> Optional[Dict]:
        """دریافت اطلاعات SSL certificate"""
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'not_after': cert.get('notAfter'),
                        'san': [x[1] for x in cert.get('subjectAltName', []) if x[0] == 'DNS']
                    }
        except:
            return None
    
    async def certificate_transparency_search(self, domain: str) -> Set[str]:
        """جستجو در Certificate Transparency logs"""
        subdomains = set()
        
        try:
            # استفاده از crt.sh API
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        
                        # استخراج subdomainها
                        for line in name_value.split('\n'):
                            line = line.strip()
                            if line.endswith(f'.{domain}') and '*' not in line:
                                subdomain = line.replace(f'.{domain}', '')
                                if subdomain and '.' not in subdomain:
                                    subdomains.add(subdomain)
                                    
        except Exception:
            pass
        
        return subdomains
    
    async def scan_subdomains(self, domain: str, use_wordlist: bool = True, use_ct: bool = True) -> List[Dict]:
        """اسکن کامل subdomainها"""
        all_subdomains = set()
        
        # اضافه کردن wordlist
        if use_wordlist:
            all_subdomains.update(self.wordlist)
        
        # اضافه کردن نتایج Certificate Transparency
        if use_ct:
            ct_subdomains = await self.certificate_transparency_search(domain)
            all_subdomains.update(ct_subdomains)
        
        # محدود کردن تعداد همزمان
        semaphore = asyncio.Semaphore(20)
        results = []
        
        async def scan_subdomain(subdomain):
            async with semaphore:
                # DNS lookup
                dns_result = await self.dns_lookup(subdomain, domain)
                if not dns_result:
                    return None
                
                # HTTP check
                http_result = await self.http_check(dns_result['subdomain'])
                
                return {
                    'subdomain': dns_result['subdomain'],
                    'ips': dns_result['ips'],
                    'dns': dns_result,
                    'http': http_result,
                    'has_web': bool(http_result)
                }
        
        # اجرای اسکن‌ها
        tasks = [scan_subdomain(sub) for sub in all_subdomains]
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # فیلتر کردن نتایج معتبر
        for result in scan_results:
            if isinstance(result, dict) and result:
                results.append(result)
        
        return sorted(results, key=lambda x: x['subdomain'])

@client.on(events.NewMessage(pattern=r"\.subdomain(?:\s+(.+))?", outgoing=True))
async def subdomain_scanner(event):
    domain_input = event.pattern_match.group(1)
    reply = await event.get_reply_message()

    if not domain_input and reply:
        domain_input = reply.message.strip()

    if not domain_input:
        await event.reply("""
🔍 **Advanced Subdomain Scanner**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
**استفاده:**
`.subdomain example.com`
`.subdomain target.org`

**قابلیت‌های پیشرفته:**
• اسکن با 70+ wordlist رایج
• جستجوی Certificate Transparency
• بررسی DNS resolution
• تست HTTP/HTTPS
• استخراج SSL certificate info
• تحلیل web server headers
• شناسایی redirect chains
• گزارش تفصیلی امنیتی

**روش‌های کشف:**
🔍 **DNS Bruteforce** - تست wordlist
🔐 **Certificate Transparency** - جستجوی CT logs
🌐 **HTTP Discovery** - بررسی وب سرویس‌ها
📋 **SSL Analysis** - تحلیل گواهینامه‌ها

**اطلاعات ارائه شده:**
• IP addresses و DNS records
• HTTP status codes و redirects
• Web server information
• SSL certificate details
• Page titles و content info

⚠️ **هشدار:** فقط برای تست دامنه‌های خودتان!
        """.strip())
        return

    # حذف http/https از ابتدای دامنه
    domain = domain_input.replace('http://', '').replace('https://', '').split('/')[0]
    
    await event.edit(f"🔍 شروع اسکن پیشرفته subdomain برای {domain}...")

    try:
        scanner = SubdomainScanner()
        
        async with aiohttp.ClientSession() as session:
            scanner.session = session
            
            # شروع اسکن
            await event.edit(f"🔍 جستجوی Certificate Transparency و DNS bruteforce...")
            
            results = await scanner.scan_subdomains(domain, use_wordlist=True, use_ct=True)
            
            await event.edit("📊 تحلیل نتایج و ارزیابی امنیتی...")

        if results:
            # تجزیه و تحلیل نتایج
            web_services = [r for r in results if r['has_web']]
            ssl_enabled = []
            interesting_subdomains = []
            
            for result in results:
                subdomain = result['subdomain']
                
                # بررسی SSL
                if result['http'] and 'https' in result['http']:
                    https_info = result['http']['https']
                    if https_info.get('status_code'):
                        ssl_enabled.append(subdomain)
                
                # شناسایی subdomainهای جالب
                interesting_keywords = ['admin', 'api', 'dev', 'test', 'staging', 'backup', 'db', 'git', 'jenkins']
                if any(keyword in subdomain.lower() for keyword in interesting_keywords):
                    interesting_subdomains.append(subdomain)
            
            # ساخت لیست نتایج
            subdomain_list = []
            for i, result in enumerate(results[:20]):  # نمایش حداکثر 20 subdomain
                subdomain = result['subdomain']
                ips = ', '.join(result['ips'][:2])  # نمایش حداکثر 2 IP
                
                # تعیین آیکون
                if result['has_web']:
                    if subdomain in ssl_enabled:
                        icon = "🟢"
                    else:
                        icon = "🟡"
                else:
                    icon = "🔵"
                
                # اطلاعات اضافی
                extra_info = ""
                if result['http']:
                    for protocol, info in result['http'].items():
                        if info.get('status_code'):
                            extra_info += f" [{protocol.upper()}: {info['status_code']}]"
                
                subdomain_list.append(f"  {icon} **{subdomain}** ({ips}){extra_info}")
            
            subdomains_text = "\n".join(subdomain_list)
            if len(results) > 20:
                subdomains_text += f"\n  ... و {len(results) - 20} subdomain دیگر"
            
            # آمار کلی
            stats = {
                'total': len(results),
                'web_enabled': len(web_services),
                'ssl_enabled': len(ssl_enabled),
                'interesting': len(interesting_subdomains)
            }
            
            # subdomainهای جالب
            interesting_text = "\n".join([f"  ⚠️ **{sub}**" for sub in interesting_subdomains[:5]])
            if not interesting_text:
                interesting_text = "  ✅ subdomain مشکوک یافت نشد"
            
            # تعیین سطح خطر
            risk_score = len(interesting_subdomains) + (stats['web_enabled'] // 3)
            if risk_score >= 5:
                risk_level = "🟡 متوسط"
                risk_color = "🟡"
            elif risk_score >= 2:
                risk_level = "🟢 پایین"
                risk_color = "🟢"
            else:
                risk_level = "🟢 امن"
                risk_color = "🟢"
            
            msg = f"""
{risk_color} **گزارش Subdomain Scanner**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 **دامنه:** {domain}
🔍 **Subdomainهای یافت شده:** {stats['total']}
🌐 **دارای وب سرویس:** {stats['web_enabled']}
🔐 **SSL فعال:** {stats['ssl_enabled']}
⚠️ **مشکوک:** {stats['interesting']}
🚨 **سطح خطر:** {risk_level}

📋 **لیست Subdomainها:**
{subdomains_text}

⚠️ **Subdomainهای مشکوک:**
{interesting_text}

📊 **آمار تفصیلی:**
  🔹 DNS Resolution Rate: {(stats['total']/len(scanner.wordlist)*100):.1f}%
  🔹 Web Service Rate: {(stats['web_enabled']/stats['total']*100):.1f}%
  🔹 SSL Adoption: {(stats['ssl_enabled']/max(stats['web_enabled'],1)*100):.1f}%

💡 **توصیه‌های امنیتی:**
  • بررسی دسترسی subdomainهای مشکوک
  • فعال‌سازی SSL برای همه سرویس‌ها
  • حذف subdomainهای غیرضروری
  • پیکربندی مناسب DNS security

⚠️ **هشدار:** این اطلاعات فقط برای بهبود امنیت دامنه شما!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            """.strip()
        else:
            msg = f"""
🟢 **گزارش Subdomain Scanner**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 **دامنه:** {domain}
🔍 **نتیجه:** هیچ subdomain قابل دسترسی یافت نشد
🚨 **سطح خطر:** 🟢 امن

📈 **تحلیل:**
  🔹 DNS bruteforce انجام شد
  🔹 Certificate Transparency بررسی شد
  🔹 هیچ subdomain عمومی یافت نشد

✅ **دامنه surface attack کمی دارد**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            """.strip()

        await event.edit(msg)

    except Exception as e:
        await event.edit(f"⚠️ خطا در اسکن subdomain: {str(e)}")

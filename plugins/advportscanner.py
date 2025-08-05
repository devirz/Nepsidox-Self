# plugins/advportscanner.py

from telethon import events
from client import client
import asyncio
import socket
import time
import ipaddress
import struct
import random
from typing import List, Dict, Optional, Tuple

class AdvancedPortScanner:
    def __init__(self):
        self.common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 27017: 'MongoDB',
            8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 9200: 'Elasticsearch', 11211: 'Memcached'
        }
        
        self.port_ranges = {
            'common': [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017],
            'web': [80, 443, 8080, 8443, 8000, 8888, 9000, 3000, 5000, 7000, 9090, 8081, 8082],
            'database': [1433, 3306, 5432, 1521, 27017, 6379, 11211, 9042, 7000, 7001],
            'remote': [22, 23, 3389, 5900, 5901, 5902, 4899, 1494, 3283],
            'mail': [25, 110, 143, 993, 995, 587, 465, 2525],
            'full': list(range(1, 1001))
        }
        
        self.service_banners = {}
        
    async def scan_port(self, host: str, port: int, timeout: float = 1.0) -> Dict:
        """اسکن یک پورت مشخص"""
        try:
            # ایجاد connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            # تلاش برای دریافت banner
            banner = await self._grab_banner(reader, writer, port)
            
            writer.close()
            await writer.wait_closed()
            
            return {
                'port': port,
                'status': 'open',
                'service': self.common_ports.get(port, 'unknown'),
                'banner': banner,
                'response_time': timeout
            }
            
        except asyncio.TimeoutError:
            return {
                'port': port,
                'status': 'filtered',
                'service': self.common_ports.get(port, 'unknown'),
                'banner': None,
                'response_time': timeout
            }
        except ConnectionRefusedError:
            return {
                'port': port,
                'status': 'closed',
                'service': self.common_ports.get(port, 'unknown'),
                'banner': None,
                'response_time': 0
            }
        except Exception:
            return {
                'port': port,
                'status': 'error',
                'service': self.common_ports.get(port, 'unknown'),
                'banner': None,
                'response_time': 0
            }
    
    async def _grab_banner(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int) -> Optional[str]:
        """دریافت banner از سرویس"""
        try:
            # ارسال درخواست مناسب برای هر سرویس
            if port == 80:
                writer.write(b'GET / HTTP/1.1\r\nHost: target\r\n\r\n')
            elif port == 443:
                # برای HTTPS نیاز به SSL handshake داریم
                return "HTTPS/SSL"
            elif port == 21:
                # FTP معمولاً خودش banner می‌فرستد
                pass
            elif port == 22:
                # SSH معمولاً خودش banner می‌فرستد
                pass
            elif port == 25:
                writer.write(b'EHLO test\r\n')
            elif port == 110:
                writer.write(b'USER test\r\n')
            elif port == 143:
                writer.write(b'A001 CAPABILITY\r\n')
            
            await writer.drain()
            
            # خواندن response
            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            banner = data.decode('utf-8', errors='ignore').strip()
            
            return banner[:200] if banner else None
            
        except Exception:
            return None
    
    async def scan_host(self, host: str, port_range: str = 'common', max_concurrent: int = 50) -> List[Dict]:
        """اسکن یک هاست با پورت‌های مشخص"""
        ports = self.port_ranges.get(port_range, self.port_ranges['common'])
        
        # محدود کردن تعداد اتصالات همزمان
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def scan_with_semaphore(port):
            async with semaphore:
                return await self.scan_port(host, port)
        
        # اجرای اسکن‌ها به صورت همزمان
        tasks = [scan_with_semaphore(port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # فیلتر کردن نتایج معتبر
        valid_results = []
        for result in results:
            if isinstance(result, dict) and result['status'] == 'open':
                valid_results.append(result)
        
        return sorted(valid_results, key=lambda x: x['port'])
    
    async def ping_host(self, host: str) -> bool:
        """بررسی در دسترس بودن هاست"""
        try:
            # تلاش برای اتصال به پورت 80 یا 443
            for port in [80, 443, 22, 21]:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=2.0
                    )
                    writer.close()
                    await writer.wait_closed()
                    return True
                except:
                    continue
            return False
        except:
            return False
    
    def analyze_services(self, scan_results: List[Dict]) -> Dict:
        """تحلیل سرویس‌های یافت شده"""
        analysis = {
            'total_open_ports': len(scan_results),
            'services': {},
            'security_issues': [],
            'recommendations': []
        }
        
        for result in scan_results:
            service = result['service']
            port = result['port']
            banner = result['banner']
            
            if service not in analysis['services']:
                analysis['services'][service] = []
            analysis['services'][service].append(port)
            
            # بررسی مسائل امنیتی
            if port in [21, 23]:  # FTP, Telnet
                analysis['security_issues'].append(f"Insecure service {service} on port {port}")
            elif port == 22 and banner and 'OpenSSH' in banner:
                if any(old_version in banner for old_version in ['OpenSSH_5', 'OpenSSH_6']):
                    analysis['security_issues'].append(f"Outdated SSH version detected: {banner[:50]}")
            elif port in [1433, 3306, 5432] and not any(secure_port in [r['port'] for r in scan_results] for secure_port in [443, 22]):
                analysis['security_issues'].append(f"Database service {service} exposed without secure access")
        
        # توصیه‌های امنیتی
        if 21 in [r['port'] for r in scan_results]:
            analysis['recommendations'].append("Consider using SFTP instead of FTP")
        if 23 in [r['port'] for r in scan_results]:
            analysis['recommendations'].append("Replace Telnet with SSH")
        if len(scan_results) > 10:
            analysis['recommendations'].append("Consider closing unnecessary ports")
        
        return analysis

@client.on(events.NewMessage(pattern=r"\.portscan(?:\s+(.+))?", outgoing=True))
async def advanced_port_scanner(event):
    args = event.pattern_match.group(1)
    
    if not args:
        await event.reply("""
🔍 **Advanced Port Scanner**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
**استفاده:**
`.portscan example.com`
`.portscan 192.168.1.1 web`
`.portscan target.com database`
`.portscan 10.0.0.1 full`

**انواع اسکن:**
🔴 **common** - پورت‌های رایج (پیش‌فرض)
🟠 **web** - سرویس‌های وب
🟡 **database** - پایگاه‌های داده
🟢 **remote** - دسترسی راه دور
🔵 **mail** - سرویس‌های ایمیل
⚫ **full** - اسکن کامل (1-1000)

**قابلیت‌های پیشرفته:**
• اسکن همزمان با کنترل سرعت
• تشخیص سرویس و banner grabbing
• تحلیل امنیتی خودکار
• شناسایی آسیب‌پذیری‌های رایج
• توصیه‌های بهبود امنیت
• گزارش تفصیلی حرفه‌ای

⚠️ **هشدار:** فقط برای تست شبکه‌های خودتان!
        """.strip())
        return

    parts = args.split()
    host = parts[0]
    scan_type = parts[1] if len(parts) > 1 else 'common'
    
    if scan_type not in ['common', 'web', 'database', 'remote', 'mail', 'full']:
        scan_type = 'common'

    await event.edit(f"🔍 شروع اسکن پیشرفته پورت برای {host}...")

    try:
        scanner = AdvancedPortScanner()
        
        # بررسی در دسترس بودن هاست
        await event.edit(f"📡 بررسی دسترسی به {host}...")
        
        if not await scanner.ping_host(host):
            await event.edit(f"❌ هاست {host} در دسترس نیست یا فایروال دارد")
            return
        
        # شروع اسکن
        port_count = len(scanner.port_ranges[scan_type])
        await event.edit(f"🔍 اسکن {port_count} پورت در حال انجام...")
        
        start_time = time.time()
        results = await scanner.scan_host(host, scan_type, max_concurrent=30)
        scan_duration = time.time() - start_time
        
        # تحلیل نتایج
        await event.edit("📊 تحلیل نتایج و ارزیابی امنیتی...")
        analysis = scanner.analyze_services(results)
        
        if results:
            # ساخت لیست پورت‌های باز
            open_ports = []
            for result in results[:15]:  # نمایش حداکثر 15 پورت
                port = result['port']
                service = result['service']
                banner_info = ""
                
                if result['banner']:
                    banner_short = result['banner'][:30] + '...' if len(result['banner']) > 30 else result['banner']
                    banner_info = f" ({banner_short})"
                
                # تعیین آیکون بر اساس امنیت
                if port in [21, 23]:
                    icon = "🔴"
                elif port in [22, 443]:
                    icon = "🟢"
                elif port in [80, 8080]:
                    icon = "🟡"
                else:
                    icon = "🔵"
                
                open_ports.append(f"  {icon} **{port}** - {service}{banner_info}")
            
            ports_text = "\n".join(open_ports)
            if len(results) > 15:
                ports_text += f"\n  ... و {len(results) - 15} پورت دیگر"
            
            # خلاصه سرویس‌ها
            services_summary = []
            for service, ports in analysis['services'].items():
                port_list = ', '.join(map(str, ports[:3]))
                if len(ports) > 3:
                    port_list += f" (+{len(ports)-3} more)"
                services_summary.append(f"  🔹 **{service}:** {port_list}")
            
            services_text = "\n".join(services_summary[:10])
            
            # مسائل امنیتی
            security_text = "\n".join([f"  ⚠️ {issue}" for issue in analysis['security_issues'][:5]])
            if not security_text:
                security_text = "  ✅ مشکل امنیتی جدی یافت نشد"
            
            # توصیه‌ها
            recommendations_text = "\n".join([f"  💡 {rec}" for rec in analysis['recommendations'][:3]])
            if not recommendations_text:
                recommendations_text = "  ✅ پیکربندی مناسب است"
            
            # تعیین سطح خطر
            risk_score = len(analysis['security_issues']) * 2 + (len(results) // 5)
            if risk_score >= 8:
                risk_level = "🔴 بالا"
                risk_color = "🔴"
            elif risk_score >= 4:
                risk_level = "🟡 متوسط"
                risk_color = "🟡"
            else:
                risk_level = "🟢 پایین"
                risk_color = "🟢"
            
            msg = f"""
{risk_color} **گزارش کامل Port Scanner**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 **هدف:** {host}
⏱️ **مدت اسکن:** {scan_duration:.1f} ثانیه
🔍 **نوع اسکن:** {scan_type.upper()}
📊 **پورت‌های تست شده:** {port_count}
✅ **پورت‌های باز:** {len(results)}
🚨 **سطح خطر:** {risk_level}

🔓 **پورت‌های باز:**
{ports_text}

🛠️ **سرویس‌های شناسایی شده:**
{services_text}

⚠️ **مسائل امنیتی:**
{security_text}

💡 **توصیه‌های امنیتی:**
{recommendations_text}

📈 **آمار کلی:**
  🔹 تعداد سرویس‌های مختلف: {len(analysis['services'])}
  🔹 مسائل امنیتی: {len(analysis['security_issues'])}
  🔹 امتیاز ریسک: {risk_score}/20

⚠️ **هشدار:** این اطلاعات فقط برای بهبود امنیت شبکه خودتان!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            """.strip()
        else:
            msg = f"""
🟢 **گزارش Port Scanner**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 **هدف:** {host}
⏱️ **مدت اسکن:** {scan_duration:.1f} ثانیه
🔍 **نوع اسکن:** {scan_type.upper()}
📊 **پورت‌های تست شده:** {port_count}
✅ **نتیجه:** هیچ پورت بازی یافت نشد
🚨 **سطح خطر:** 🟢 امن

📈 **تحلیل:**
  🔹 همه پورت‌های تست شده بسته هستند
  🔹 فایروال احتمالاً فعال است
  🔹 سطح امنیت مناسب است

✅ **سیستم در برابر اسکن پورت محافظت شده است**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            """.strip()

        await event.edit(msg)

    except Exception as e:
        await event.edit(f"⚠️ خطا در اسکن پورت: {str(e)}")

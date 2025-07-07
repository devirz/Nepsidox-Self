# plugins/sysmon.py

from telethon import events
from client import client
import psutil
import platform
import datetime
import socket

def mask_ip(ip):
    parts = ip.split(".")
    if len(parts) == 4:
        parts[1] = parts[2] = "***"
        return ".".join(parts)
    return ip

def get_size(bytes, suffix="B"):
    """تبدیل سایز بایت به خوانا مثل MB, GB"""
    factor = 1024
    for unit in ["", "K", "M", "G", "T"]:
        if bytes < factor:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= factor

@client.on(events.NewMessage(pattern=r"\.sys$", outgoing=True))
async def sys_monitor(event):
    boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
    uptime = datetime.datetime.now() - boot_time
    hostname = socket.gethostname()
    ip_address_raw = socket.gethostbyname(hostname)
    ip_address = mask_ip(ip_address_raw)
    
    # CPU
    cpu_usage = psutil.cpu_percent(interval=1)
    cpu_cores = psutil.cpu_count(logical=False)
    cpu_threads = psutil.cpu_count()

    # RAM
    ram = psutil.virtual_memory()
    ram_total = get_size(ram.total)
    ram_used = get_size(ram.used)
    ram_percent = ram.percent

    # Disk
    disk = psutil.disk_usage("/")
    disk_total = get_size(disk.total)
    disk_used = get_size(disk.used)
    disk_percent = disk.percent

    # Network
    net = psutil.net_io_counters()
    bytes_sent = get_size(net.bytes_sent)
    bytes_recv = get_size(net.bytes_recv)

    os_info = platform.system() + " " + platform.release()

    message = f"""
🖥️ **وضعیت سیستم**
━━━━━━━━━━━━━━━━━━
📡 IP: `{ip_address}`
🧠 RAM: {ram_used} / {ram_total} ({ram_percent}%)
⚙️ CPU: {cpu_usage}%  | Cores: {cpu_cores} | Threads: {cpu_threads}
💽 Disk: {disk_used} / {disk_total} ({disk_percent}%)
📤 آپلود: {bytes_sent}
📥 دانلود: {bytes_recv}
⏳ Uptime: {str(uptime).split('.')[0]}
🖥️ OS: {os_info}
━━━━━━━━━━━━━━━━━━
    """.strip()

    await event.reply(message)

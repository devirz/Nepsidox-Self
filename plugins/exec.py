# plugins/telexec.py

from telethon import events
from client import client
import io
import contextlib
import traceback
import asyncio

@client.on(events.NewMessage(pattern=r"\.exec(?:\s+)?([\s\S]+)?", outgoing=True))
async def exec_async_code(event):
    raw_code = event.pattern_match.group(1)
    reply = await event.get_reply_message()

    if not raw_code and reply:
        raw_code = reply.text.strip()
    
    if not raw_code:
        await event.reply("❌ لطفاً کدی وارد کن یا ریپلای کن به پیام حاوی کد.")
        return

    raw_code = raw_code.strip("`").strip()

    # آماده‌سازی محیط اجرا
    stdout = io.StringIO()
    exec_locals = {}

    # بدنه تابع async بسازیم
    func_code = f"async def __exec_func():\n"
    for line in raw_code.splitlines():
        func_code += f"    {line}\n"  # با این کار کد رو داخل تابع async می‌بریم

    try:
        # اجرای تابع async به صورت داینامیک
        exec(func_code, {
            "client": event.client,
            "event": event,
            "__name__": "__main__"
        }, exec_locals)

        with contextlib.redirect_stdout(stdout):
            await exec_locals["__exec_func"]()

        result = stdout.getvalue().strip()
        if result:
            await event.reply(f"📤 **خروجی:**\n`{result[:4000]}`")
        else:
            await event.reply("✅ با موفقیت اجرا شد (بدون خروجی).")
    except Exception:
        error_text = traceback.format_exc(limit=2)
        await event.reply(f"❌ به ارور خورد:\n`{error_text[:4000]}`")
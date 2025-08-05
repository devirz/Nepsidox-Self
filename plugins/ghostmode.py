# plugins/ghostmode.py

from telethon import events
from client import client
from telethon.tl.functions.account import UpdateProfileRequest
from telethon.tl.types import Message
import asyncio

# حالت فعال یا غیرفعال
ghost_mode = {"active": False, "delay": 10, "original_name": None}

@client.on(events.NewMessage(pattern=r"\.ghost (on|off)(?: (\d+))?", outgoing=True))
async def toggle_ghost(event):
    global ghost_mode
    action = event.pattern_match.group(1)
    delay = event.pattern_match.group(2)

    if action == "on":
        ghost_mode["active"] = True
        ghost_mode["delay"] = int(delay) if delay else 10

        # ذخیره نام قبلی و تغییر نام (اختیاری)
        me = await event.client.get_me()
        ghost_mode["original_name"] = (me.first_name, me.last_name)
        await event.client(UpdateProfileRequest(first_name="👻", last_name=""))

        await event.reply(f"✅ حالت ناشناس فعال شد. پیام‌ها پس از {ghost_mode['delay']} ثانیه پاک می‌شوند.")
    else:
        ghost_mode["active"] = False
        ghost_mode["delay"] = 0

        # بازگرداندن نام اصلی
        if ghost_mode["original_name"]:
            await event.client(UpdateProfileRequest(
                first_name=ghost_mode["original_name"][0],
                last_name=ghost_mode["original_name"][1] or ""
            ))
        await event.reply("❌ حالت ناشناس غیرفعال شد.")

# حذف خودکار پیام‌های ارسالی
@events.register(events.NewMessage(outgoing=True))
async def auto_delete(event: Message):
    global ghost_mode

    if ghost_mode["active"]:
        await asyncio.sleep(ghost_mode["delay"])
        try:
            await event.delete()
        except Exception:
            pass  # شاید پیام پاک‌شدنی نباشه (مثلاً تو گروه محدود)


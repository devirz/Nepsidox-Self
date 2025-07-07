# plugins/whois.py

from telethon import events
from telethon.tl.types.users import UserFull
from client import client
from telethon.tl.functions.users import GetFullUserRequest
from datetime import datetime

@client.on(events.NewMessage(pattern=r"\.whois(?:\s+(.+))?", outgoing=True))
async def whois(event):
    reply = await event.get_reply_message()
    input_str = event.pattern_match.group(1)

    if reply:
        user = await event.client.get_entity(reply.sender_id)
    elif input_str:
        try:
            user = await event.client.get_entity(input_str)
        except Exception:
            await event.reply("❌ کاربر پیدا نشد.")
            return
    else:
        user = await event.client.get_entity(event.sender_id)

    full: UserFull = await event.client(GetFullUserRequest(user.id))
    profile = full.full_user
    about = profile.about if hasattr(profile, "about") else "—"
    first = full.users[0].first_name or ""
    last = full.users[0].last_name or ""
    name = f"{first} {last}".strip()
    username = f"@{full.users[0].username}" if full.users[0].username else "—"
    user_id = profile.id
    dc_id = full.users[0].photo.dc_id if full.users[0].photo else "—"
    blocked = "Yes" if profile.blocked else "No"
    spamed = "Yes" if profile.settings.report_spam else "No"
    result = f"""
👤 **اطلاعات کاربر:**
━━━━━━━━━━━━━━━━━━
🆔 ID: `{user_id}`
👤 اسم: `{name}`
🔗 یوزرنیم: {username}
📝 بیو: `{about}`
📦 DC ID: `{dc_id}`
📆 تاریخ ثبت: `{profile.profile_photo.date.strftime('%Y-%m-%d %H:%M:%S') if profile.profile_photo.date else 'نامشخص'}`
🚨 بلاک شده: {blocked}
⚠️ اسپم: {spamed}
━━━━━━━━━━━━━━━━━━
    """.strip()

    await event.reply(result)

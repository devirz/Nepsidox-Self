from telethon import events
from config import OWNER_ID
from client import client
from core.dispatcher import COMMAND_HANDLERS
import re

def register_handlers():
    @client.on(events.NewMessage(from_users=OWNER_ID))
    async def dispatcher(event):
        text = event.raw_text.strip()
        for pattern, handler in COMMAND_HANDLERS:
            match = re.match(pattern, text)
            if match:
                try:
                    await handler(event, *match.groups())
                except Exception as e:
                    await event.reply(f"❌ خطا در اجرای دستور: `{str(e)}`")
                break

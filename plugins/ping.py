from client import client
from telethon import events

@client.on(events.NewMessage(pattern=r'^[Pp][Ii][Nn][Gg]$'))
async def ping_handler(event):
    # city = event.pattern_match.group(1)
    await event.edit("**PONG!**")

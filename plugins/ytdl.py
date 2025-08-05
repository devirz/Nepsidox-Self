from telethon import events
from config import OWNER_ID
from yt_dlp import YoutubeDL
from client import client
import os
import tempfile

@client.on(events.NewMessage(pattern=r'^ytdl (.+)$', from_users=OWNER_ID, outgoing=True))
async def ytdl(event):
    url = event.pattern_match.group(1)
    await event.reply("⏳ Downloading audio...")

    ydl_opts = {
        'format': 'bestaudio/best',
        'outtmpl': os.path.join(tempfile.gettempdir(), '%(title)s.%(ext)s'),
        'postprocessors': [{
            'key': 'FFmpegExtractAudio',
            'preferredcodec': 'mp3',
            'preferredquality': '320',
        }],
        'quiet': True,
        'no_warnings': True,
    }

    try:
        with YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=True)
            filename = ydl.prepare_filename(info).replace(info['ext'], 'mp3')

        await event.client.send_file(
            event.chat_id,
            filename,
            caption=f"🎵 {info['title']}",
            reply_to=event.message
        )
    except Exception as e:
        await event.reply(f"❌ Error downloading audio: {str(e)}")
    finally:
        if 'filename' in locals() and os.path.exists(filename):
            os.remove(filename)
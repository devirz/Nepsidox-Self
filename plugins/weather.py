from core.dispatcher import register_command
import aiohttp

@register_command(r'^\.weather (.+)$')
async def weather_handler(event, city):
    await event.edit(f"🔍 در حال دریافت وضعیت هوا برای [**{city}**] ...")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://wttr.in/{city}?format=3") as resp:
                if resp.status == 200:
                    data = await resp.text()
                    await event.edit(f"🌦 {data}")
                else:
                    await event.edit("⚠️ پیدا نشد!")
    except Exception as e:
        await event.reply(f"خطا: {e}")

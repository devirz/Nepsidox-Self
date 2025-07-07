from textfx import typeeffect
from client import client
import loader
import handlers
import asyncio
from utils.logger import logger, install_global_handler

install_global_handler()  # فعال‌سازی لاگ کردن تمام خطاهای برنامه
typeeffect("[+] Running Nepsidox Selfbot!\n", color="cyan")
async def main():
    await client.start()
    loader.load_plugins()
    logger.info("✔️ Plugins Loaded...")
    handlers.register_handlers()
    logger.info("🤖 Selfbot is active...")
    await client.run_until_disconnected()

try:
    asyncio.run(main())
except KeyboardInterrupt:
    logger.debug("Exitting App...")
    client.disconnect()
    exit()
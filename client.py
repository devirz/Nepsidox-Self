from telethon import TelegramClient
import config

client = TelegramClient(config.SESSION_NAME, config.API_ID, config.API_HASH)
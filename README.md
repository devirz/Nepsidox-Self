# 🤖 Nepsidox-Self | Telegram Selfbot

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Stars](https://img.shields.io/github/stars/devirz/Nepsidox-Self?style=social)](https://github.com/devirz/Nepsidox-Self/stargazers)
[![Forks](https://img.shields.io/github/forks/devirz/Nepsidox-Self?style=social)](https://github.com/devirz/Nepsidox-Self/fork)
[![Last Commit](https://img.shields.io/github/last-commit/devirz/Nepsidox-Self.svg)](https://github.com/devirz/Nepsidox-Self/commits/main)

A modern, modular, and easy-to-use Telegram selfbot written in Python.  
**⚠️ Use responsibly! Selfbots can violate Telegram’s Terms of Service.**

---

## ✨ Features

- Fast and lightweight Python core 🐍
- Modular plugin support 🧩
- Easy setup and configuration ⚙️
- Actively maintained and open source 🚀

---

## 📦 Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/devirz/Nepsidox-Self.git
   cd Nepsidox-Self
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

---

## ⚙️ Configuration

Before running the selfbot, set your credentials and preferences in the `config.py` file:

```python
API_ID = 123456         # Get this from https://my.telegram.org
API_HASH = 'your_api_hash'  # Get this from https://my.telegram.org
OWNER_ID = 123456789    # Your Telegram user ID; the bot only responds to this account
SESSION_NAME = 'NepsidoxSelf'  # Session name for Telethon
```

**How to get your API ID and API Hash:**  
Go to [my.telegram.org](https://my.telegram.org), log in, click on ‘API development tools’, and create a new application.

---

## ▶️ Running the Bot

Just run:

```bash
python bot.py
```

The bot will start using the configuration provided in `config.py`.

---

## 🧩 Adding Plugins

Nepsidox-Self supports custom plugins for extending functionality!

1. **Create Your Plugin:**  
   Write your own plugin as a `.py` file. Here’s a sample template:

   ```python
   # plugins/my_plugin.py
   from telethon import events

   @client.on(events.NewMessage(pattern=r"\.hello"))
   async def handler(event):
       await event.reply("Hello, world!")
   ```

2. **Add Plugin to the Plugins Folder:**  
   Place your plugin file inside the `plugins/` directory.

3. **Restart the Bot:**  
   The bot auto-loads plugins from the `plugins/` folder at startup.

---

## 🛡️ Disclaimer

> **Warning:** Selfbots are against the Terms of Service of Telegram and may result in account suspension or termination. Use at your own risk.

---

## 📝 License

This project is open source and available under the MIT License.

---

**Made with ❤️ by [devirz](https://github.com/devirz)**
